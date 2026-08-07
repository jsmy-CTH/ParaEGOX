use paraegox_inspection::{
    InspectionFreshnessV1, InspectionHealthV1, InspectionLivenessV1, InspectionReadinessV1,
    LocalInspectionOverallV1, LocalInspectionRecordV1, LocalInspectionSnapshotV1,
    LocalInspectionSnapshotV2, NodeInspectionRecordV2,
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Position},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::app::{
    ChatApp, MessageDelivery, MessageRole, UiConnectionState, terminal_failure_label,
};

pub(crate) fn render(frame: &mut Frame<'_>, app: &ChatApp) {
    let status_height = match (
        app.inspection_status_v2().is_some(),
        app.inspection_status().is_some(),
    ) {
        (true, _) => 4,
        (false, true) => 3,
        (false, false) => 2,
    };
    let [history_area, input_area, status_area] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(status_height),
    ])
    .areas(frame.area());

    let history_lines = history_lines(app);
    let available_history_lines = usize::from(history_area.height.saturating_sub(2));
    let history_scroll = history_lines.len().saturating_sub(available_history_lines);
    let history_scroll = u16::try_from(history_scroll).unwrap_or(u16::MAX);
    let history = Paragraph::new(history_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.options().title()),
        )
        .wrap(Wrap { trim: false })
        .scroll((history_scroll, 0));
    frame.render_widget(history, history_area);

    let input_prefix = Line::from(app.input()[..app.cursor()].to_owned());
    let cursor_width = input_prefix.width();
    let inner_width = usize::from(input_area.width.saturating_sub(2)).max(1);
    let horizontal_scroll = cursor_width.saturating_sub(inner_width.saturating_sub(1));
    let input = Paragraph::new(app.input())
        .block(Block::default().borders(Borders::ALL).title("Message"))
        .scroll((0, u16::try_from(horizontal_scroll).unwrap_or(u16::MAX)));
    frame.render_widget(input, input_area);

    if input_area.width > 2 && input_area.height > 2 {
        let visible_cursor = cursor_width.saturating_sub(horizontal_scroll);
        let visible_cursor = u16::try_from(visible_cursor).unwrap_or(u16::MAX);
        frame.set_cursor_position(Position::new(
            input_area
                .x
                .saturating_add(1)
                .saturating_add(visible_cursor),
            input_area.y.saturating_add(1),
        ));
    }

    let status = status_lines(app);
    frame.render_widget(
        Paragraph::new(status).wrap(Wrap { trim: true }),
        status_area,
    );
}

fn history_lines(app: &ChatApp) -> Vec<Line<'static>> {
    if app.history().is_empty() {
        return vec![Line::from(Span::styled(
            "Connected chat messages will appear here.",
            Style::default().fg(Color::DarkGray),
        ))];
    }

    let mut lines = Vec::new();
    for message in app.history() {
        let (prefix, color) = match message.role {
            MessageRole::User => ("you", Color::Cyan),
            MessageRole::Assistant => ("agent", Color::Green),
        };
        let status = match message.delivery {
            MessageDelivery::Sending => " [sending]".to_owned(),
            MessageDelivery::CancellationRequested => " [cancel requested]".to_owned(),
            MessageDelivery::Delivered => String::new(),
            MessageDelivery::TerminalFailure(failure) => {
                format!(" [failed: {}]", terminal_failure_label(failure))
            }
        };

        let mut content_lines = message.text.lines();
        let first = content_lines.next().unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{prefix}> "),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(first.to_owned()),
            Span::styled(status, Style::default().fg(Color::Yellow)),
        ]));
        for continuation in content_lines {
            lines.push(Line::from(format!("       {continuation}")));
        }
    }
    lines
}

fn status_lines(app: &ChatApp) -> Vec<Line<'static>> {
    let (connection, color) = match app.connection() {
        UiConnectionState::Connecting => ("connecting", Color::Yellow),
        UiConnectionState::Connected => ("connected", Color::Green),
        UiConnectionState::Disconnected => ("disconnected", Color::DarkGray),
        UiConnectionState::Failed(_) => ("failed", Color::Red),
    };
    let activity = if app.is_pending() { " | sending" } else { "" };
    let notice = app
        .notice()
        .map_or_else(String::new, |notice| format!(" | {notice}"));
    let mut lines = vec![Line::from(vec![
        Span::styled(
            app.options().mode_label().to_owned(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(connection, Style::default().fg(color)),
        Span::raw(activity),
        Span::raw(notice),
        Span::styled(
            " | Enter send · Esc cancel/exit · Ctrl-C/Ctrl-Q exit",
            Style::default().fg(Color::DarkGray),
        ),
    ])];
    if let Some(snapshot) = app.inspection_status_v2() {
        lines.extend(inspection_status_lines_v2(snapshot));
    } else if let Some(snapshot) = app.inspection_status() {
        lines.extend(inspection_status_lines(snapshot));
    }
    lines
}

fn inspection_status_lines_v2(snapshot: &LocalInspectionSnapshotV2) -> [Line<'static>; 3] {
    let node = snapshot.node();
    let node_coordinate = match (node.registration_epoch(), node.status_sequence()) {
        (Some(registration_epoch), Some(status_sequence)) => {
            format!(" · registration e{registration_epoch} · status s{status_sequence}")
        }
        _ => String::new(),
    };
    let first = format!(
        "Node-local startup snapshot {} r{} | NodeDaemon {}{node_coordinate}",
        overall_label(snapshot.overall()),
        snapshot.projection_revision(),
        projected_node_label(node),
    );
    let records = snapshot.base_snapshot().records();
    let second = format!(
        "Authority {} | Deployment {} | Runtime {}",
        projected_source_label(records[0]),
        projected_source_label(records[1]),
        projected_source_label(records[2]),
    );
    let third = format!(
        "Fabric {} | Agent {} | {}",
        projected_source_label(records[3]),
        projected_source_label(records[4]),
        five_owner_health_label(records),
    );
    [
        Line::from(Span::styled(
            first,
            Style::default().fg(overall_color(snapshot.overall())),
        )),
        Line::from(Span::styled(second, Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled(third, Style::default().fg(Color::DarkGray))),
    ]
}

fn inspection_status_lines(snapshot: &LocalInspectionSnapshotV1) -> [Line<'static>; 2] {
    let records = snapshot.records();
    let first = format!(
        "Node-local startup snapshot {} r{} | Authority {} | Deployment {} | Runtime {}",
        overall_label(snapshot.overall()),
        snapshot.projection_revision(),
        projected_source_label(records[0]),
        projected_source_label(records[1]),
        projected_source_label(records[2]),
    );
    let health = five_owner_health_label(records);
    let second = format!(
        "Fabric {} | Agent {} | {health}",
        projected_source_label(records[3]),
        projected_source_label(records[4]),
    );
    [
        Line::from(Span::styled(
            first,
            Style::default().fg(overall_color(snapshot.overall())),
        )),
        Line::from(Span::styled(second, Style::default().fg(Color::DarkGray))),
    ]
}

fn five_owner_health_label(records: &[LocalInspectionRecordV1; 5]) -> String {
    if records
        .iter()
        .all(|record| record.health() == InspectionHealthV1::Unknown)
    {
        "health unreported".to_owned()
    } else {
        let healthy = records
            .iter()
            .filter(|record| record.health() == InspectionHealthV1::Healthy)
            .count();
        let degraded = records
            .iter()
            .filter(|record| record.health() == InspectionHealthV1::Degraded)
            .count();
        let faulted = records
            .iter()
            .filter(|record| record.health() == InspectionHealthV1::Faulted)
            .count();
        format!("health {healthy} healthy/{degraded} degraded/{faulted} faulted")
    }
}

const fn overall_label(overall: LocalInspectionOverallV1) -> &'static str {
    match overall {
        LocalInspectionOverallV1::Ready => "READY",
        LocalInspectionOverallV1::Degraded => "DEGRADED",
        LocalInspectionOverallV1::Unavailable => "UNAVAILABLE",
        LocalInspectionOverallV1::Unknown => "UNKNOWN",
    }
}

const fn overall_color(overall: LocalInspectionOverallV1) -> Color {
    match overall {
        LocalInspectionOverallV1::Ready => Color::Green,
        LocalInspectionOverallV1::Degraded => Color::Yellow,
        LocalInspectionOverallV1::Unavailable => Color::Red,
        LocalInspectionOverallV1::Unknown => Color::DarkGray,
    }
}

const fn projected_source_label(record: LocalInspectionRecordV1) -> &'static str {
    match record.freshness() {
        InspectionFreshnessV1::Stale => "stale",
        InspectionFreshnessV1::Partitioned => "partitioned",
        InspectionFreshnessV1::Missing => "missing",
        InspectionFreshnessV1::Fresh => match (record.readiness(), record.liveness()) {
            (InspectionReadinessV1::Ready, InspectionLivenessV1::Live) => "ready",
            (InspectionReadinessV1::Ready, InspectionLivenessV1::Unknown) => "recorded-ready",
            (InspectionReadinessV1::NotReady, _) => "not-ready",
            (InspectionReadinessV1::Degraded, _) => "degraded",
            (InspectionReadinessV1::Blocked, _) => "blocked",
            (InspectionReadinessV1::Unknown, _) => "unknown",
            (InspectionReadinessV1::Ready, _) => "invalid-ready",
        },
    }
}

const fn projected_node_label(record: NodeInspectionRecordV2) -> &'static str {
    match record.freshness() {
        InspectionFreshnessV1::Stale => "stale",
        InspectionFreshnessV1::Partitioned => "partitioned",
        InspectionFreshnessV1::Missing => "missing",
        InspectionFreshnessV1::Fresh => match (record.readiness(), record.liveness()) {
            (InspectionReadinessV1::Ready, InspectionLivenessV1::Live) => "ready",
            (InspectionReadinessV1::Ready, InspectionLivenessV1::Unknown) => "recorded-ready",
            (InspectionReadinessV1::NotReady, _) => "not-ready",
            (InspectionReadinessV1::Degraded, _) => "degraded",
            (InspectionReadinessV1::Blocked, _) => "blocked",
            (InspectionReadinessV1::Unknown, _) => "unknown",
            (InspectionReadinessV1::Ready, _) => "invalid-ready",
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use paraegox_agent_contracts::{
        AgentConversationDeckRunId, AgentConversationRequestId, AgentConversationRequestV1,
        AgentConversationSessionId, AgentConversationTerminalV1, AgentConversationTurnId,
    };
    use paraegox_inspection::{
        InspectionFeatureSupportV1, InspectionObservationClockRefV1, InspectionReasonV1,
        InspectionSourceAvailabilityV1, InspectionSourceOwnerV1, InspectionSourceSlotV1,
        LocalInspectionProjectionInputV1, LocalInspectionProjectionInputV2,
        NodeInspectionFactFieldsV2, NodeInspectionFactV2, NodeInspectionSourceSlotV2,
        project_local_inspection_snapshot_v2,
    };
    use paraegox_kernel::digest::Digest32;
    use ratatui::{Terminal, backend::TestBackend};

    use crate::{
        ConversationClient, ConversationClientError, ConversationClientEvent,
        ConversationConnectionState, TuiOptions,
    };

    use super::*;

    struct RenderClient {
        events: VecDeque<ConversationClientEvent>,
        request: Option<AgentConversationRequestV1>,
    }

    impl ConversationClient for RenderClient {
        fn begin_connect(&mut self) -> Result<(), ConversationClientError> {
            Ok(())
        }

        fn poll_event(
            &mut self,
        ) -> Result<Option<ConversationClientEvent>, ConversationClientError> {
            Ok(self.events.pop_front())
        }

        fn submit_turn(
            &mut self,
            input: &str,
            deadline_budget_nanos: u64,
        ) -> Result<AgentConversationRequestV1, ConversationClientError> {
            let request = AgentConversationRequestV1::try_new(
                AgentConversationDeckRunId::try_from_bytes([4; 16]).expect("DeckRun"),
                AgentConversationSessionId::try_from_bytes([1; 16]).expect("session"),
                AgentConversationTurnId::try_from_bytes([2; 16]).expect("turn"),
                AgentConversationRequestId::try_from_bytes([3; 16]).expect("request"),
                deadline_budget_nanos,
                input,
            )
            .expect("request");
            self.request = Some(request.clone());
            Ok(request)
        }

        fn request_cancel(
            &mut self,
            _request: &AgentConversationRequestV1,
        ) -> Result<(), ConversationClientError> {
            Ok(())
        }

        fn close(&mut self) -> Result<(), ConversationClientError> {
            Ok(())
        }
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        let mut output = String::new();
        for y in area.top()..area.bottom() {
            for x in area.left()..area.right() {
                output.push_str(buffer[(x, y)].symbol());
            }
            output.push('\n');
        }
        output
    }

    fn inspection_snapshot_v2() -> LocalInspectionSnapshotV2 {
        let clock = InspectionObservationClockRefV1::try_from_bytes([0x31; 16]).expect("clock");
        let slot = |owner: InspectionSourceOwnerV1| {
            InspectionSourceSlotV1::try_new(owner, [owner as u8 + 0x40; 16], None)
                .expect("missing owner slot")
        };
        let base = LocalInspectionProjectionInputV1::try_new(
            clock,
            [
                slot(InspectionSourceOwnerV1::Authority),
                slot(InspectionSourceOwnerV1::DeploymentController),
                slot(InspectionSourceOwnerV1::RuntimeHost),
                slot(InspectionSourceOwnerV1::FabricService),
                slot(InspectionSourceOwnerV1::AgentService),
            ],
        )
        .expect("five-owner input");
        let node = NodeInspectionFactV2::try_new(NodeInspectionFactFieldsV2 {
            node_ref: [0x61; 16],
            node_incarnation_ref: [0x62; 16],
            registration_epoch: 31,
            status_sequence: 41,
            observation_clock_ref: clock,
            observed_at_nanos: 100,
            valid_until_nanos: 200,
            availability: InspectionSourceAvailabilityV1::Observed,
            liveness: InspectionLivenessV1::Live,
            readiness: InspectionReadinessV1::Ready,
            health: InspectionHealthV1::Healthy,
            feature_support: InspectionFeatureSupportV1::AllRequiredSupported,
            reason: InspectionReasonV1::None,
            node_status_digest: Digest32::from_bytes([0x63; 32]),
        })
        .expect("NodeDaemon fact");
        let node = NodeInspectionSourceSlotV2::try_new([0x61; 16], [0x62; 16], Some(node))
            .expect("NodeDaemon slot");
        let input = LocalInspectionProjectionInputV2::try_new(base, node).expect("v2 input");
        project_local_inspection_snapshot_v2([0x21; 16], clock, 7, 150, &input)
            .expect("v2 startup snapshot")
    }

    #[test]
    fn test_backend_renders_connection_sending_and_terminal_history() {
        let options =
            TuiOptions::try_new("ParaEGOX Chat", "TEST ADAPTER", 5_000_000_000).expect("options");
        let mut app = ChatApp::new(options);
        let mut client = RenderClient {
            events: VecDeque::from([ConversationClientEvent::ConnectionChanged(
                ConversationConnectionState::Connected,
            )]),
            request: None,
        };
        app.start(&mut client);
        app.poll(&mut client);
        app.handle_paste("hello");
        app.handle_key(
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Enter,
                crossterm::event::KeyModifiers::NONE,
            ),
            &mut client,
        );

        let mut terminal = Terminal::new(TestBackend::new(80, 12)).expect("terminal");
        terminal.draw(|frame| render(frame, &app)).expect("draw");
        let sending = buffer_text(&terminal);
        assert!(sending.contains("ParaEGOX Chat"));
        assert!(sending.contains("you> hello [sending]"));
        assert!(sending.contains("TEST ADAPTER | connected | sending"));

        let request = client.request.clone().expect("request");
        client.events.push_back(ConversationClientEvent::Terminal(
            AgentConversationTerminalV1::try_success(&request, "typed answer").expect("terminal"),
        ));
        app.poll(&mut client);
        terminal.draw(|frame| render(frame, &app)).expect("draw");
        let terminal_text = buffer_text(&terminal);
        assert!(terminal_text.contains("you> hello"));
        assert!(terminal_text.contains("agent> typed answer"));
        assert!(!terminal_text.contains("[sending]"));
    }

    #[test]
    fn v2_status_renders_node_and_embedded_five_owner_snapshot_without_private_material() {
        let options =
            TuiOptions::try_new("ParaEGOX Chat", "TEST ADAPTER", 5_000_000_000).expect("options");
        let app = ChatApp::new_with_inspection_status_v2(options, inspection_snapshot_v2());
        let mut terminal = Terminal::new(TestBackend::new(140, 14)).expect("terminal");

        terminal.draw(|frame| render(frame, &app)).expect("draw");

        let output = buffer_text(&terminal);
        assert!(output.contains("Node-local startup snapshot UNKNOWN r7 | NodeDaemon ready"));
        assert!(output.contains("registration e31 · status s41"));
        assert!(output.contains("Authority missing | Deployment missing | Runtime missing"));
        assert!(output.contains("Fabric missing | Agent missing | health unreported"));
        assert!(!output.contains(&"61".repeat(16)));
        assert!(!output.contains(&"63".repeat(32)));
        assert!(!output.contains("socket"));
        assert!(!output.contains("token"));
    }
}
