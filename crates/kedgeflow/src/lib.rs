//! Bounded v0.9 reference implementation. Profiles remain proposed contracts.
pub mod adapter;
pub mod admission;
pub mod auth;
pub mod broker;
pub mod clock;
pub mod config;
pub mod contracts;
pub mod control;
pub mod control_config;
pub mod endpoint;
pub mod error;
pub mod execution_status;
pub mod gateway;
pub mod grant_reference;
pub mod issuance;
pub mod ledger;
pub mod policy;
pub mod schema;
pub mod server;
pub mod tls;

pub mod governance;
pub mod governance_config;
mod governance_ledger;
pub mod governance_service;

pub mod gateway_control;

pub mod operation_status;

pub mod recovery;
pub mod recovery_config;
mod recovery_ledger;

pub mod outcome_report;
pub mod outcome_report_client;
pub mod outcome_report_config;
mod outcome_report_ledger;
pub mod outcome_report_service;

pub mod lineage;
pub mod lineage_config;

pub mod control_history;
pub mod control_history_config;
mod control_history_ledger;
pub mod control_history_verify;

pub mod control_bindings;
pub mod restore;
pub mod supervision;
pub mod supervision_config;
mod supervision_ledger;

pub mod shared_auth;

pub mod broker_authorization;

pub mod exchange_identity;

pub mod broker_config;
pub mod broker_service;
pub mod target_token;

pub mod identity_refresh;

pub mod postgres_action;
pub mod postgres_adapter;
pub mod postgres_config;
pub mod postgres_store;
pub mod postgres_target;

pub mod leaf_action;

pub mod coordination;
pub mod postgres_custody;
pub mod postgres_socket;
pub mod review;
pub mod review_config;
pub mod review_evidence;
pub mod review_service;

pub mod leases;

mod lease_http;

pub mod reserved_leaf;

pub mod reservation_history;

pub mod reserved_lineage;

pub mod a2a_root;
pub mod a2a_root_service;

pub mod hierarchical_leaf;

pub mod saga;

pub mod saga_config;

pub mod saga_forward;

pub mod compensation;

pub mod compensation_config;

pub mod action_domain;

pub mod action_domain_config;

pub mod compensation_execution;

pub mod compensation_adapter;
pub mod compensation_target;
pub mod compensation_target_config;
pub mod compensation_target_http;
pub mod postgres_compensation;

pub mod compensation_lineage;

pub mod family;
