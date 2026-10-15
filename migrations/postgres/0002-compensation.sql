-- RFC 0048. Apply separately as the protected non-agent schema owner.
-- No changes to the original reservation action or its retained outcomes.
BEGIN;
CREATE SCHEMA kf_compensation;
REVOKE ALL ON SCHEMA kf_compensation FROM PUBLIC;
CREATE TABLE kf_compensation.snapshot (
    tenant text NOT NULL,
    contract_digest text NOT NULL,
    request jsonb NOT NULL,
    reservation text NOT NULL,
    PRIMARY KEY (tenant, contract_digest)
);
CREATE TABLE kf_compensation.attempt (
    tenant text NOT NULL,
    attempt_id text NOT NULL,
    contract_digest text NOT NULL,
    root_id text NOT NULL,
    grant_digest text NOT NULL,
    request jsonb NOT NULL,
    outcome jsonb NOT NULL,
    PRIMARY KEY (tenant, attempt_id),
    UNIQUE (tenant, contract_digest),
    UNIQUE (tenant, root_id),
    UNIQUE (tenant, grant_digest)
);
REVOKE ALL ON ALL TABLES IN SCHEMA kf_compensation FROM PUBLIC;

CREATE FUNCTION kf_compensation.valid_request(q jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE k text; f jsonb;
BEGIN
    IF jsonb_typeof(q) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(q)) <> 17
       OR q->>'profile' IS DISTINCT FROM 'KF-POSTGRES-COMPENSATION-0.1-draft'
       OR q->>'action' IS DISTINCT FROM 'kedgeflow.compensation.restore.v1' THEN
        RETURN false;
    END IF;
    FOREACH k IN ARRAY ARRAY['contract_digest','forward_grant_digest','restore_state_digest'] LOOP
        IF jsonb_typeof(q->k) IS DISTINCT FROM 'string'
           OR (q->>k) !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
    END LOOP;
    FOREACH k IN ARRAY ARRAY['forward_root_id','forward_attempt_id'] LOOP
        IF jsonb_typeof(q->k) IS DISTINCT FROM 'string'
           OR (q->>k) !~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$' THEN RETURN false; END IF;
    END LOOP;
    f := q - ARRAY['contract_digest','forward_grant_digest','forward_root_id',
                   'forward_attempt_id','restore_state_digest'];
    f := f || jsonb_build_object('profile','KF-POSTGRES-RESERVATION-0.1-draft',
        'action','postgres.reservation.set.v1','reservation','validation');
    RETURN kf_reservation.valid_request(f);
END;
$$;

-- Owner-only capture. Neither the executor nor query login receives this port.
CREATE FUNCTION kf_compensation.capture(q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r kf_reservation.resource%ROWTYPE; saved kf_compensation.snapshot%ROWTYPE;
        f jsonb; state_bytes bytea; state_digest text;
BEGIN
    IF jsonb_typeof(q) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(q)) <> 6
       OR EXISTS (SELECT FROM jsonb_object_keys(q) AS keys(key) WHERE key <> ALL
         (ARRAY['tenant','conflict_domain','resource','baseline_version','contract_digest','restore_state_digest']))
       OR jsonb_typeof(q->'contract_digest') IS DISTINCT FROM 'string'
       OR (q->>'contract_digest') !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(q->'restore_state_digest') IS DISTINCT FROM 'string'
       OR (q->>'restore_state_digest') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid protected restore snapshot' USING ERRCODE='22023';
    END IF;
    f := jsonb_build_object('profile','KF-POSTGRES-RESERVATION-0.1-draft',
        'action','postgres.reservation.set.v1','tenant',q->'tenant',
        'conflict_domain',q->'conflict_domain','resource',q->'resource',
        'expected_version',q->'baseline_version','attempt_id','validation',
        'grant_digest',q->'contract_digest','root_id','validation',
        'fence',1,'reservation','validation',
        'gateway_workload','spiffe://validation/snapshot','expires_at',1);
    IF NOT kf_reservation.valid_request(f) THEN
        RAISE EXCEPTION 'invalid protected restore snapshot' USING ERRCODE='22023';
    END IF;
    -- Serialize concurrent captures, forward effects and resource writers.
    SELECT * INTO r FROM kf_reservation.resource
        WHERE tenant=q->>'tenant' AND resource_id=q->'resource'->>'id' FOR UPDATE;
    SELECT * INTO saved FROM kf_compensation.snapshot
        WHERE tenant=q->>'tenant' AND contract_digest=q->>'contract_digest';
    IF FOUND THEN
        IF saved.request IS DISTINCT FROM q THEN
            RAISE EXCEPTION 'conflicting restore snapshot' USING ERRCODE='22023';
        END IF;
        RETURN saved.request;
    END IF;
    IF r.tenant IS NULL OR NOT r.active OR r.conflict_domain<>q->>'conflict_domain'
       OR r.incarnation<>q->'resource'->>'incarnation'
       OR r.version<>(q->>'baseline_version')::bigint
       OR r.reservation !~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$'
       OR EXISTS (SELECT FROM kf_reservation.attempt WHERE tenant=r.tenant
           AND request->'resource'=q->'resource'
           AND request->'expected_version'=q->'baseline_version') THEN
        RAISE EXCEPTION 'restore snapshot is not an unexecuted baseline' USING ERRCODE='22023';
    END IF;
    -- These strings are restricted to ASCII tokens. The exact byte sequence is
    -- the KF-JSON-0.2 canonical {reservation,resource:{id,incarnation}} object.
    state_bytes := convert_to('KedgeFlow/KF-JSON-0.2/postgres-restore-state','UTF8')
        || decode('00','hex')
        || convert_to('{"reservation":'||to_json(r.reservation)::text
          ||',"resource":{"id":'||to_json(r.resource_id)::text
          ||',"incarnation":'||to_json(r.incarnation)::text||'}}','UTF8');
    state_digest := encode(sha256(state_bytes),'hex');
    IF state_digest<>q->>'restore_state_digest' THEN
        RAISE EXCEPTION 'restore snapshot digest mismatch' USING ERRCODE='22023';
    END IF;
    INSERT INTO kf_compensation.snapshot VALUES (r.tenant,q->>'contract_digest',q,r.reservation);
    RETURN q;
END;
$$;

CREATE FUNCTION kf_compensation.barrier(p_tenant text, p_contract text,
    p_attempt text, p_grant text, p_root text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s kf_compensation.snapshot%ROWTYPE; f kf_reservation.attempt%ROWTYPE;
        r kf_reservation.resource%ROWTYPE;
BEGIN
    SELECT * INTO s FROM kf_compensation.snapshot
        WHERE tenant=p_tenant AND contract_digest=p_contract;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO f FROM kf_reservation.attempt
        WHERE tenant=p_tenant AND attempt_id=p_attempt;
    IF NOT FOUND OR f.grant_digest<>p_grant OR f.root_id<>p_root
       OR f.outcome->>'status' IS DISTINCT FROM 'committed'
       OR f.request->'resource' IS DISTINCT FROM s.request->'resource'
       OR f.request->'conflict_domain' IS DISTINCT FROM s.request->'conflict_domain'
       OR f.request->'expected_version' IS DISTINCT FROM s.request->'baseline_version'
       OR f.outcome->'post_version' IS DISTINCT FROM
          to_jsonb((s.request->>'baseline_version')::bigint+1) THEN RETURN NULL; END IF;
    SELECT * INTO r FROM kf_reservation.resource
        WHERE tenant=p_tenant AND resource_id=s.request->'resource'->>'id' FOR SHARE;
    IF NOT FOUND OR NOT r.active OR r.incarnation<>s.request->'resource'->>'incarnation'
       OR r.conflict_domain<>s.request->>'conflict_domain'
       OR r.version<>(s.request->>'baseline_version')::bigint+1
       OR r.last_fence<>(f.request->>'fence')::bigint
       OR r.reservation<>f.request->>'reservation' THEN RETURN NULL; END IF;
    RETURN jsonb_build_object('contract_digest',p_contract,'forward_outcome',f.outcome,
        'resource',s.request->'resource','observed_version',r.version,
        'restore_state_digest',s.request->'restore_state_digest');
END;
$$;

CREATE FUNCTION kf_compensation.apply(q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE saved kf_compensation.attempt%ROWTYPE; s kf_compensation.snapshot%ROWTYPE;
        r kf_reservation.resource%ROWTYPE; f kf_reservation.attempt%ROWTYPE;
        result jsonb; inserted integer;
BEGIN
    IF NOT kf_compensation.valid_request(q) THEN
        RAISE EXCEPTION 'invalid compensation request' USING ERRCODE='22023';
    END IF;
    result := jsonb_build_object('profile',q->>'profile','request',q,
        'status','guard_rejected','post_version',NULL);
    INSERT INTO kf_compensation.attempt VALUES
        (q->>'tenant',q->>'attempt_id',q->>'contract_digest',q->>'root_id',q->>'grant_digest',q,result)
        ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS inserted = ROW_COUNT;
    IF inserted=0 THEN
        SELECT * INTO saved FROM kf_compensation.attempt
            WHERE tenant=q->>'tenant' AND attempt_id=q->>'attempt_id';
        IF NOT FOUND OR saved.request IS DISTINCT FROM q THEN
            RAISE EXCEPTION 'conflicting retained compensation binding' USING ERRCODE='22023';
        END IF;
        RETURN saved.outcome;
    END IF;
    SELECT * INTO s FROM kf_compensation.snapshot
        WHERE tenant=q->>'tenant' AND contract_digest=q->>'contract_digest';
    SELECT * INTO f FROM kf_reservation.attempt
        WHERE tenant=q->>'tenant' AND attempt_id=q->>'forward_attempt_id';
    SELECT * INTO r FROM kf_reservation.resource
        WHERE tenant=q->>'tenant' AND resource_id=q->'resource'->>'id' FOR UPDATE;
    IF s.tenant IS NOT NULL AND f.tenant IS NOT NULL AND r.tenant IS NOT NULL
       AND s.request->'resource'=q->'resource'
       AND s.request->'conflict_domain'=q->'conflict_domain'
       AND s.request->'restore_state_digest'=q->'restore_state_digest'
       AND (s.request->>'baseline_version')::bigint+1=(q->>'expected_version')::bigint
       AND f.grant_digest=q->>'forward_grant_digest'
       AND f.root_id=q->>'forward_root_id'
       AND f.outcome->>'status'='committed'
       AND f.request->'resource'=q->'resource'
       AND f.request->'conflict_domain'=q->'conflict_domain'
       AND f.request->'expected_version'=s.request->'baseline_version'
       AND f.outcome->'post_version'=q->'expected_version'
       AND r.active AND r.incarnation=q->'resource'->>'incarnation'
       AND r.conflict_domain=q->>'conflict_domain'
       AND r.version=(q->>'expected_version')::bigint
       AND r.last_fence=(f.request->>'fence')::bigint
       AND r.reservation=f.request->>'reservation'
       AND r.last_fence<(q->>'fence')::bigint
       AND floor(extract(epoch FROM clock_timestamp())*1000)<(q->>'expires_at')::bigint THEN
        UPDATE kf_reservation.resource SET reservation=s.reservation,
            version=version+1,last_fence=(q->>'fence')::bigint
            WHERE tenant=r.tenant AND resource_id=r.resource_id;
        result := jsonb_build_object('profile',q->>'profile','request',q,
            'status','committed','post_version',r.version+1);
        UPDATE kf_compensation.attempt SET outcome=result
            WHERE tenant=q->>'tenant' AND attempt_id=q->>'attempt_id';
    END IF;
    RETURN result;
END;
$$;

CREATE FUNCTION kf_compensation.lookup(p_tenant text,p_attempt text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT outcome FROM kf_compensation.attempt WHERE tenant=p_tenant AND attempt_id=p_attempt;
$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kf_compensation FROM PUBLIC;
COMMIT;
