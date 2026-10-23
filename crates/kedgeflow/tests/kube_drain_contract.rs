//! Closed profile/binding vectors. These do not qualify actual native/Kube work.
use kedgeflow::{
    contracts::{self, Action},
    kube_drain::{self, Contract, NamespacedPin, ObjectPin},
    kube_drain_api::{self, Inventory, NodeView, PodView},
};
use serde_json::{Value, json};
fn pin(name: &str, uid: &str) -> ObjectPin {
    ObjectPin {
        name: name.into(),
        uid: uid.into(),
    }
}
fn contract() -> Contract {
    serde_json::from_value(json!({"profile":kube_drain::PROFILE,"cluster_uid":"realm-1","api_origin":"https://cluster.test/","ca_sha256":"a".repeat(64),"node":pin("node-1","node-uid-1"),"generation":1,"availability_nodes":[pin("node-1","node-uid-1"),pin("node-2","node-uid-2"),pin("node-3","node-uid-3")],"minimum_ready_nodes":2,"workload":{"deployment":{"namespace":"orders","object":pin("orders","deployment-1")},"generation":1,"replica_set":pin("orders-rs","rs-1"),"pdb":pin("orders","pdb-1"),"pdb_generation":1,"pdb_min_available":2,"minimum_available":2},"allowed_daemon_sets":[],"allowed_mirror_pods":[],"maximum_pods":8,"maximum_requests":16,"maximum_deferred_ms":60000,"grace_period_seconds":1})).unwrap()
}
fn node(c: &Contract) -> NodeView {
    NodeView {
        object: c.node.clone(),
        resource_version: "opaque-node-version".into(),
        ready: true,
        unschedulable: false,
        operation: None,
        annotations_present: false,
    }
}
fn pod(c: &Contract) -> PodView {
    PodView {
        object: NamespacedPin {
            namespace: "orders".into(),
            object: pin("orders-original", "pod-original"),
        },
        resource_version: "opaque-pod-version".into(),
        owner_kind: "ReplicaSet".into(),
        owner_api_version: "apps/v1".into(),
        owner: c.workload.replica_set.clone(),
        ready: true,
        deleting: false,
        mirror: false,
    }
}
fn inventory(c: &Contract) -> Inventory {
    Inventory {
        profile: kube_drain::PROFILE.into(),
        contract_digest: c.digest().unwrap(),
        from: 1000,
        until: 1001,
        cluster_uid: c.cluster_uid.clone(),
        nodes: c
            .availability_nodes
            .iter()
            .map(|p| NodeView {
                object: p.clone(),
                ..node(c)
            })
            .collect(),
        target_pods: vec![pod(c)],
        deployment_uid: c.workload.deployment.object.uid.clone(),
        deployment_generation: 1,
        observed_generation: 1,
        available: 3,
        replica_set_uid: c.workload.replica_set.uid.clone(),
        pdb_uid: c.workload.pdb.uid.clone(),
        pdb_generation: 1,
        pdb_min_available: 2,
        pdb_disruptions_allowed: 1,
    }
}
#[test]
fn closed_contract_binds_realm_generation_and_exact_scope() {
    let c = contract();
    let raw = contracts::canonical(&json!(c)).unwrap();
    assert_eq!(Contract::decode(&raw).unwrap(), c);
    for (field, value) in [
        ("unknown", json!(true)),
        ("cluster_uid", Value::Null),
        ("api_origin", json!("http://cluster.test/")),
        ("api_origin", json!("https://cluster.test/path")),
        ("generation", json!(0)),
        ("maximum_requests", json!(97)),
        ("maximum_deferred_ms", json!(3600001)),
    ] {
        let mut p = json!(c);
        p[field] = value;
        assert!(
            Contract::decode(&serde_json::to_vec(&p).unwrap()).is_err(),
            "{field}"
        );
    }
    let duplicate =
        String::from_utf8(raw.clone())
            .unwrap()
            .replacen('{', "{\"profile\":\"wrong\",", 1);
    assert!(Contract::decode(duplicate.as_bytes()).is_err());
    let mut other = c.clone();
    other.cluster_uid = "realm-2".into();
    assert_ne!(other.resource().unwrap(), c.resource().unwrap());
    assert_ne!(
        other.parameter_schema().unwrap(),
        c.parameter_schema().unwrap()
    );
    other = c.clone();
    other.generation += 1;
    assert_ne!(other.digest().unwrap(), c.digest().unwrap());
    assert_ne!(
        other.parameter_schema().unwrap(),
        c.parameter_schema().unwrap()
    );
    other = c.clone();
    other.node.name = "bad..node".into();
    assert!(other.validate().is_err());
    other = c.clone();
    other.availability_nodes[1] = other.availability_nodes[0].clone();
    assert!(other.validate().is_err());
}
#[test]
fn named_level_c_binding_cannot_inherit_legacy_fencing() {
    let c = contract();
    let a = Action {
        id: kube_drain::ACTION.into(),
        version: "1.0".into(),
        digest: "b".repeat(64),
    };
    let resource = c.resource().unwrap();
    contracts::validate_action_adapter(&a, &kube_drain::adapter_contract(), &resource, None)
        .unwrap();
    assert!(
        contracts::validate_adapter_contract(&kube_drain::adapter_contract(), &resource, None)
            .is_err()
    );
    let mut legacy = a.clone();
    legacy.id = "legacy.mock".into();
    assert!(
        contracts::validate_action_adapter(
            &legacy,
            &kube_drain::adapter_contract(),
            &resource,
            None
        )
        .is_err()
    );
    let mut fenced = kube_drain::adapter_contract();
    fenced["level"] = json!("Level_A");
    fenced["guard_primitive"] = json!("FencingToken");
    fenced["fence_parameter"] = json!("fence");
    fenced["guard_scope"] = json!([c.node.name]);
    assert!(contracts::validate_action_adapter(&a, &fenced, &resource, None).is_err());
    let schema = c.parameter_schema().unwrap();
    kedgeflow::leaf_action::validate_schema(&a.id, &a.version, &schema).unwrap();
    let mut bad = schema.clone();
    bad["additionalProperties"] = json!(true);
    assert!(kube_drain::validate_schema("1.0", &bad).is_err());
    let args = json!({"node":c.node.name,"expected_version":1});
    assert_eq!(
        kedgeflow::leaf_action::bind(&a.id, &a.version, &args, &resource, "expected_version")
            .unwrap(),
        1
    );
    for args in [
        json!({"node":"node-2","expected_version":1}),
        json!({"node":c.node.name,"expected_version":1,"fence":9}),
        json!({"node":c.node.name,"expected_version":"1"}),
    ] {
        assert!(kube_drain::bind("1.0", &args, &resource, "expected_version").is_err());
    }
}
#[test]
fn requests_pin_original_uids_and_opaque_versions_without_delete_fallback() {
    let c = contract();
    let n = node(&c);
    let operation = "c".repeat(64);
    let patch = kube_drain_api::cordon_request(&c, &n, &operation).unwrap();
    assert_eq!(patch[0]["value"], n.object.uid);
    assert_eq!(patch[1]["value"], n.resource_version);
    let p = pod(&c);
    let request = kube_drain_api::eviction_request(&c, &p).unwrap();
    assert_eq!(request["kind"], "Eviction");
    assert_eq!(request["apiVersion"], "policy/v1");
    assert_eq!(
        request["deleteOptions"]["preconditions"]["uid"],
        p.object.object.uid
    );
    assert_eq!(
        request["deleteOptions"]["preconditions"]["resourceVersion"],
        p.resource_version
    );
    let mut other = n.clone();
    other.unschedulable = true;
    assert!(kube_drain_api::cordon_request(&c, &other, &operation).is_err());
    other = n.clone();
    other.operation = Some("d".repeat(64));
    assert!(kube_drain_api::cordon_request(&c, &other, &operation).is_err());
    let mut wrong = p.clone();
    wrong.owner_api_version = "fake/v1".into();
    assert!(kube_drain_api::eviction_request(&c, &wrong).is_err());
    wrong = p.clone();
    wrong.deleting = true;
    assert!(kube_drain_api::eviction_request(&c, &wrong).is_err());
    let mut wrong = n;
    wrong.resource_version.clear();
    assert!(kube_drain_api::cordon_request(&c, &wrong, &operation).is_err());
}
#[test]
fn complete_inventory_rejects_missing_nodes_unapproved_owners_and_stale_generation() {
    let c = contract();
    let i = inventory(&c);
    i.availability(&c).unwrap();
    let mut bad = i.clone();
    bad.nodes.pop();
    assert!(bad.validate(&c).is_err());
    bad = i.clone();
    bad.nodes[0].object.uid = "recreated-node".into();
    assert!(bad.validate(&c).is_err());
    bad = i.clone();
    bad.target_pods[0].owner.uid = "another-rs".into();
    assert!(bad.validate(&c).is_err());
    bad = i.clone();
    bad.deployment_generation += 1;
    assert!(bad.validate(&c).is_err());
    bad = i.clone();
    bad.cluster_uid = "another-realm".into();
    assert!(bad.validate(&c).is_err());
    bad = i.clone();
    bad.available = 1;
    assert!(bad.availability(&c).is_err());
    bad = i.clone();
    bad.nodes[1].unschedulable = true;
    assert!(bad.availability(&c).is_err());
    bad = i.clone();
    bad.pdb_generation += 1;
    assert!(bad.validate(&c).is_err());
}

#[test]
fn physical_extension_cannot_normalize_explicit_null_into_legacy_absence() {
    let node = json!({"child_id":"child-0","operation_key":"a".repeat(64),"depends_on":[],"forward_trust":{},"compound_trust":null});
    let decoded: kedgeflow::family_saga::Node = serde_json::from_value(node.clone()).unwrap();
    assert_eq!(json!(decoded), node);
    for value in [Value::Null, json!([]), json!(false)] {
        let mut bad = node.clone();
        bad["physical"] = value;
        assert!(serde_json::from_value::<kedgeflow::family_saga::Node>(bad).is_err());
    }
}
