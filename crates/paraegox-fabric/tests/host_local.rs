use std::{net::TcpListener, time::Duration};

use paraegox_fabric::{
    FabricService, FabricServiceConfig, HandlerResponse, IngressLimits, RequestId,
    RequestResponseBindingSpec, ResponseStatus, SessionEndpoint,
};
use paraegox_kernel::digest::Digest32;
use paraegox_runtime_contracts::assignment::{BindingId, SchemaRef};

fn available_tcp_endpoint() -> SessionEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    SessionEndpoint::try_new(format!("tcp/{address}")).unwrap()
}

fn schema(marker: u8) -> SchemaRef {
    SchemaRef::try_new([marker; 16], 1, Digest32::from_bytes([marker; 32])).unwrap()
}

fn binding_spec(
    expected: Option<paraegox_fabric::BindingEpoch>,
    endpoint_key: &str,
) -> RequestResponseBindingSpec {
    RequestResponseBindingSpec::try_new(
        BindingId::from_bytes([0x31; 16]),
        expected,
        endpoint_key,
        schema(0x41),
        schema(0x42),
        IngressLimits::try_new(4, 16_384, 4_096, 4_096, Duration::from_secs(2)).unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_local_request_reply_uses_the_single_owned_session() {
    let endpoint = available_tcp_endpoint();
    let config = FabricServiceConfig::try_peer(vec![endpoint], Vec::new()).unwrap();
    let mut fabric = FabricService::start(config).await.unwrap();
    let installed = fabric
        .install_request_response_binding(binding_spec(None, "paraegox/test/session-local-request"))
        .await
        .unwrap();
    let (binding, mut requests) = installed.into_parts();
    let handler = tokio::spawn(async move {
        let request = requests.recv().await.unwrap();
        assert_eq!(request.body(), b"one-session");
        request
            .respond(HandlerResponse::Ok(b"same-owner".to_vec()))
            .unwrap();
        assert!(requests.recv().await.is_none());
    });

    let response = fabric
        .request(
            &binding,
            RequestId::try_from_bytes([0x50; 16]).unwrap(),
            b"one-session".to_vec(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), ResponseStatus::Ok);
    assert_eq!(response.body(), b"same-owner");
    fabric.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), handler)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_local_request_reply_fences_stale_epoch_and_closes_owned_sessions() {
    let endpoint = available_tcp_endpoint();
    let server_config = FabricServiceConfig::try_peer(vec![endpoint.clone()], Vec::new()).unwrap();
    let mut server = FabricService::start(server_config).await.unwrap();

    let installed_v1 = server
        .install_request_response_binding(binding_spec(None, "paraegox/test/request"))
        .await
        .unwrap();
    let (binding_v1, mut requests_v1) = installed_v1.into_parts();
    let handler_v1 = tokio::spawn(async move {
        while let Some(request) = requests_v1.recv().await {
            let mut body = b"v1:".to_vec();
            body.extend_from_slice(request.body());
            request.respond(HandlerResponse::Ok(body)).unwrap();
        }
    });

    // Opening the connector after declaration lets Zenoh's documented
    // open.return_conditions.declares synchronize the initial queryable set.
    let client_config = FabricServiceConfig::try_peer(Vec::new(), vec![endpoint]).unwrap();
    let client = FabricService::start(client_config).await.unwrap();
    let response_v1 = client
        .request(
            &binding_v1,
            RequestId::try_from_bytes([0x51; 16]).unwrap(),
            b"hello".to_vec(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(response_v1.status(), ResponseStatus::Ok);
    assert_eq!(response_v1.body(), b"v1:hello");

    let installed_v2 = server
        .install_request_response_binding(binding_spec(
            Some(binding_v1.binding_epoch()),
            "paraegox/test/request",
        ))
        .await
        .unwrap();
    let (binding_v2, mut requests_v2) = installed_v2.into_parts();
    let handler_v2 = tokio::spawn(async move {
        while let Some(request) = requests_v2.recv().await {
            let mut body = b"v2:".to_vec();
            body.extend_from_slice(request.body());
            request.respond(HandlerResponse::Ok(body)).unwrap();
        }
    });

    let stale = client
        .request(
            &binding_v1,
            RequestId::try_from_bytes([0x52; 16]).unwrap(),
            b"old".to_vec(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(stale.status(), ResponseStatus::StaleBinding);
    assert_eq!(stale.binding_epoch(), binding_v2.binding_epoch());
    assert!(stale.body().is_empty());

    let current = client
        .request(
            &binding_v2,
            RequestId::try_from_bytes([0x53; 16]).unwrap(),
            b"current".to_vec(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(current.status(), ResponseStatus::Ok);
    assert_eq!(current.body(), b"v2:current");
    assert!(server.ingress_snapshot(&binding_v1).is_none());
    assert_eq!(
        server.ingress_snapshot(&binding_v2).unwrap().queued_items(),
        0
    );

    client.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), handler_v1)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), handler_v2)
        .await
        .unwrap()
        .unwrap();
}
