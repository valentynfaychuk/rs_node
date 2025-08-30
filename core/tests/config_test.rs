use ama_core::config::{Config, ComputorType, ENTRY_SIZE, TX_SIZE, ATTESTATION_SIZE, QUORUM};

#[tokio::test]
async fn test_config_has_all_essential_elixir_parts() {
    // set up test environment
    unsafe {
        std::env::set_var("WORKFOLDER", "/tmp/test_amadeusd");
        std::env::set_var("HTTP_PORT", "8080");
        std::env::set_var("OTHERNODES", "192.168.1.1,192.168.1.2");
        std::env::set_var("TRUSTFACTOR", "0.9");
        std::env::set_var("MAX_PEERS", "500");
        std::env::set_var("ARCHIVALNODE", "true");
        std::env::set_var("AUTOUPDATE", "yes");
        std::env::set_var("COMPUTOR", "trainer");
        std::env::set_var("SNAPSHOT_HEIGHT", "12345678");
        std::env::set_var("ANR_NAME", "TestNode");
        std::env::set_var("ANR_DESC", "Test Description");
    }
    
    let config = Config::from_fs(Some("/tmp/test_config"), None).await.unwrap();
    
    // verify filesystem paths
    assert_eq!(config.work_folder, "/tmp/test_config");
    
    // verify version info
    assert_eq!(config.get_ver(), "1.1.5");
    assert_eq!(config.version_3b, [1, 1, 5]);
    
    // verify network configuration
    assert_eq!(config.http_port, 8080);
    assert_eq!(config.udp_port, 36969);
    
    // verify node discovery
    assert_eq!(config.seed_nodes, vec!["104.218.45.23", "72.9.144.110"]);
    assert_eq!(config.other_nodes, vec!["192.168.1.1", "192.168.1.2"]);
    assert_eq!(config.trust_factor, 0.9);
    assert_eq!(config.max_peers, 500);
    
    // verify seed anrs from config.exs
    assert_eq!(config.seed_anrs.len(), 1);
    let seed_anr = &config.seed_anrs[0];
    assert_eq!(seed_anr.ip4, "72.9.144.110");
    assert_eq!(seed_anr.port, 36969);
    assert_eq!(seed_anr.version, "1.1.3");
    assert_eq!(seed_anr.ts, 1755802866);
    assert_eq!(seed_anr.signature.len(), 96);
    assert_eq!(seed_anr.pk.len(), 48);
    
    // verify trainer keys
    assert_eq!(config.trainer_sk.len(), 64);
    assert_eq!(config.trainer_pk.len(), 48);
    assert!(!config.trainer_pk_b58.is_empty());
    assert_eq!(config.trainer_pop.len(), 96);
    
    // verify runtime settings
    assert!(config.archival_node);
    assert!(config.autoupdate);
    assert_eq!(config.computor_type, Some(ComputorType::Trainer));
    assert_eq!(config.snapshot_height, 12345678);
    
    // verify anr configuration
    assert_eq!(config.anr_name, Some("TestNode".to_string()));
    assert_eq!(config.anr_desc, Some("Test Description".to_string()));
    
    // verify constants from config.exs
    assert_eq!(ENTRY_SIZE, 524288);
    assert_eq!(TX_SIZE, 393216);
    assert_eq!(ATTESTATION_SIZE, 512);
    assert_eq!(QUORUM, 3);
    
    // cleanup
    let _ = tokio::fs::remove_dir_all("/tmp/test_config").await;
    let _ = tokio::fs::remove_dir_all("/tmp/test_amadeusd").await;
    
    println!("✅ All essential configuration parts from Elixir implementation are present!");
}

#[tokio::test]
async fn test_config_from_sk() {
    let sk = [42u8; 64];
    let config = Config::from_sk(sk);
    
    assert_eq!(config.trainer_sk, sk);
    assert_eq!(config.trainer_pk.len(), 48);
    assert!(!config.trainer_pk_b58.is_empty());
    assert_eq!(config.trainer_pop.len(), 96);
    assert_eq!(config.get_ver(), "1.1.5");
    assert_eq!(config.udp_port, 36969);
    assert_eq!(config.seed_nodes, vec!["104.218.45.23", "72.9.144.110"]);
}

#[tokio::test]
async fn test_config_env_parsing() {
    // test computor type parsing
    unsafe {
        std::env::remove_var("COMPUTOR");
    }
    let config = Config::from_fs(Some("/tmp/test_env"), None).await.unwrap();
    assert_eq!(config.computor_type, None);
    
    unsafe {
        std::env::set_var("COMPUTOR", "default");
    }
    let config = Config::from_fs(Some("/tmp/test_env2"), None).await.unwrap();
    assert_eq!(config.computor_type, Some(ComputorType::Default));
    
    // cleanup
    let _ = tokio::fs::remove_dir_all("/tmp/test_env").await;
    let _ = tokio::fs::remove_dir_all("/tmp/test_env2").await;
}