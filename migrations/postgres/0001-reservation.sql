-- RFC 0023 prerequisite. Apply once as the protected non-agent schema owner.
-- No agent may connect as the owner or obtain the target executor's role.
BEGIN;
CREATE SCHEMA kf_reservation;
REVOKE ALL ON SCHEMA kf_reservation FROM PUBLIC;

CREATE TABLE kf_reservation.resource (
    tenant text NOT NULL,
    conflict_domain text NOT NULL,
    resource_id text NOT NULL,
    incarnation text NOT NULL,
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    last_fence bigint NOT NULL CHECK (last_fence BETWEEN 0 AND 9007199254740991),
    reservation text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant, resource_id)
);

CREATE TABLE kf_reservation.attempt (
    tenant text NOT NULL,
    attempt_id text NOT NULL,
    root_id text NOT NULL,
    grant_digest text NOT NULL,
    request jsonb NOT NULL,
    outcome jsonb NOT NULL,
    PRIMARY KEY (tenant, attempt_id),
    UNIQUE (tenant, root_id),
    UNIQUE (tenant, grant_digest)
);
REVOKE ALL ON ALL TABLES IN SCHEMA kf_reservation FROM PUBLIC;

CREATE FUNCTION kf_reservation.valid_request(q jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE k text;
BEGIN
    IF jsonb_typeof(q) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(q)) <> 13
       OR EXISTS (SELECT FROM jsonb_object_keys(q) AS keys(key) WHERE key <> ALL
           (ARRAY['profile','action','tenant','conflict_domain','attempt_id',
                  'grant_digest','root_id','resource','expected_version','fence',
                  'reservation','gateway_workload','expires_at']))
       OR q->>'profile' IS DISTINCT FROM 'KF-POSTGRES-RESERVATION-0.1-draft'
       OR q->>'action' IS DISTINCT FROM 'postgres.reservation.set.v1' THEN
        RETURN false;
    END IF;
    FOREACH k IN ARRAY ARRAY['tenant','conflict_domain','attempt_id','root_id','reservation'] LOOP
        IF jsonb_typeof(q->k) IS DISTINCT FROM 'string'
           OR (q->>k) !~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$' THEN
            RETURN false;
        END IF;
    END LOOP;
    IF jsonb_typeof(q->'resource') IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(q->'resource')) <> 2
       OR jsonb_typeof(q->'resource'->'id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(q->'resource'->'incarnation') IS DISTINCT FROM 'string'
       OR (q->'resource'->>'id') !~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$'
       OR (q->'resource'->>'incarnation') !~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$'
       OR jsonb_typeof(q->'grant_digest') IS DISTINCT FROM 'string'
       OR (q->>'grant_digest') !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(q->'gateway_workload') IS DISTINCT FROM 'string'
       OR char_length(q->>'gateway_workload') > 2010
       OR (q->>'gateway_workload') !~ '^spiffe://[a-z0-9][A-Za-z0-9:._/-]+$' THEN
        RETURN false;
    END IF;
    FOREACH k IN ARRAY ARRAY['expected_version','fence','expires_at'] LOOP
        IF jsonb_typeof(q->k) IS DISTINCT FROM 'number'
           OR (q->>k) !~ '^[1-9][0-9]{0,15}$'
           OR (q->>k)::numeric > 9007199254740991 THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN (q->>'expected_version')::bigint < 9007199254740991;
END;
$$;

CREATE FUNCTION kf_reservation.apply(q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    saved kf_reservation.attempt%ROWTYPE;
    current_resource kf_reservation.resource%ROWTYPE;
    result jsonb;
    inserted integer;
BEGIN
    IF NOT kf_reservation.valid_request(q) THEN
        RAISE EXCEPTION 'invalid reservation request' USING ERRCODE = '22023';
    END IF;
    -- This provisional no-effect record is never visible before commit. Any
    -- exception or caller rollback undoes both it and the resource update.
    result := jsonb_build_object('profile', q->>'profile', 'request', q,
                                'status', 'guard_rejected', 'post_version', NULL);
    INSERT INTO kf_reservation.attempt
        (tenant, attempt_id, root_id, grant_digest, request, outcome)
        VALUES (q->>'tenant', q->>'attempt_id', q->>'root_id', q->>'grant_digest', q, result)
        ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS inserted = ROW_COUNT;
    IF inserted = 0 THEN
        SELECT * INTO saved FROM kf_reservation.attempt
            WHERE tenant = q->>'tenant' AND attempt_id = q->>'attempt_id';
        IF NOT FOUND OR saved.request IS DISTINCT FROM q THEN
            RAISE EXCEPTION 'conflicting retained reservation binding' USING ERRCODE = '22023';
        END IF;
        RETURN saved.outcome;
    END IF;

    SELECT * INTO current_resource FROM kf_reservation.resource
        WHERE tenant = q->>'tenant' AND resource_id = q->'resource'->>'id'
        FOR UPDATE;
    IF FOUND AND current_resource.active
       AND current_resource.conflict_domain = q->>'conflict_domain'
       AND current_resource.incarnation = q->'resource'->>'incarnation'
       AND current_resource.version = (q->>'expected_version')::bigint
       AND current_resource.last_fence < (q->>'fence')::bigint
       AND floor(extract(epoch FROM clock_timestamp()) * 1000) < (q->>'expires_at')::bigint THEN
        UPDATE kf_reservation.resource
            SET version = version + 1,
                last_fence = (q->>'fence')::bigint,
                reservation = q->>'reservation'
            WHERE tenant = q->>'tenant' AND resource_id = q->'resource'->>'id';
        result := jsonb_build_object('profile', q->>'profile', 'request', q,
                                    'status', 'committed',
                                    'post_version', current_resource.version + 1);
        UPDATE kf_reservation.attempt SET outcome = result
            WHERE tenant = q->>'tenant' AND attempt_id = q->>'attempt_id';
    END IF;
    RETURN result;
END;
$$;

CREATE FUNCTION kf_reservation.lookup(p_tenant text, p_attempt text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT outcome FROM kf_reservation.attempt
        WHERE tenant = p_tenant AND attempt_id = p_attempt;
$$;

-- Enroll narrowly scoped execution/query roles explicitly after migration.
-- PUBLIC must never obtain function access during or after installation.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kf_reservation FROM PUBLIC;
COMMIT;
