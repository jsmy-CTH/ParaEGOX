use std::io::{self, Stdout, stdout};

use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RestorationState {
    raw_mode: bool,
    alternate_screen: bool,
    cursor_hidden: bool,
}

trait RestorationOps {
    fn show_cursor(&mut self) -> io::Result<()>;
    fn leave_alternate_screen(&mut self) -> io::Result<()>;
    fn disable_raw_mode(&mut self) -> io::Result<()>;
}

struct CrosstermRestorationOps;

impl RestorationOps for CrosstermRestorationOps {
    fn show_cursor(&mut self) -> io::Result<()> {
        execute!(stdout(), Show)
    }

    fn leave_alternate_screen(&mut self) -> io::Result<()> {
        execute!(stdout(), LeaveAlternateScreen)
    }

    fn disable_raw_mode(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }
}

fn restore_with(
    state: &mut RestorationState,
    operations: &mut impl RestorationOps,
) -> io::Result<()> {
    let mut first_error = None;
    if state.cursor_hidden {
        if let Err(error) = operations.show_cursor() {
            first_error = Some(error);
        } else {
            state.cursor_hidden = false;
        }
    }
    if state.alternate_screen {
        if let Err(error) = operations.leave_alternate_screen() {
            if first_error.is_none() {
                first_error = Some(error);
            }
        } else {
            state.alternate_screen = false;
        }
    }
    if state.raw_mode {
        if let Err(error) = operations.disable_raw_mode() {
            if first_error.is_none() {
                first_error = Some(error);
            }
        } else {
            state.raw_mode = false;
        }
    }
    first_error.map_or(Ok(()), Err)
}

pub(crate) struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    restoration: RestorationState,
}

impl TerminalSession {
    pub(crate) fn enter() -> io::Result<Self> {
        let mut restoration = RestorationState::default();

        enable_raw_mode()?;
        restoration.raw_mode = true;

        let mut output = stdout();
        if let Err(error) = execute!(output, EnterAlternateScreen) {
            let _ = restore_with(&mut restoration, &mut CrosstermRestorationOps);
            return Err(error);
        }
        restoration.alternate_screen = true;

        if let Err(error) = execute!(output, Hide) {
            let _ = restore_with(&mut restoration, &mut CrosstermRestorationOps);
            return Err(error);
        }
        restoration.cursor_hidden = true;

        match Terminal::new(CrosstermBackend::new(output)) {
            Ok(terminal) => Ok(Self {
                terminal,
                restoration,
            }),
            Err(error) => {
                let _ = restore_with(&mut restoration, &mut CrosstermRestorationOps);
                Err(error)
            }
        }
    }

    pub(crate) fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    pub(crate) fn restore(&mut self) -> io::Result<()> {
        restore_with(&mut self.restoration, &mut CrosstermRestorationOps)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingOps {
        calls: Vec<&'static str>,
        fail_show: bool,
    }

    impl RestorationOps for RecordingOps {
        fn show_cursor(&mut self) -> io::Result<()> {
            self.calls.push("show");
            if self.fail_show {
                Err(io::Error::other("show failed"))
            } else {
                Ok(())
            }
        }

        fn leave_alternate_screen(&mut self) -> io::Result<()> {
            self.calls.push("leave");
            Ok(())
        }

        fn disable_raw_mode(&mut self) -> io::Result<()> {
            self.calls.push("raw-off");
            Ok(())
        }
    }

    #[test]
    fn restoration_is_reverse_ordered_and_idempotent() {
        let mut state = RestorationState {
            raw_mode: true,
            alternate_screen: true,
            cursor_hidden: true,
        };
        let mut operations = RecordingOps::default();

        restore_with(&mut state, &mut operations).expect("restore");
        restore_with(&mut state, &mut operations).expect("idempotent restore");

        assert_eq!(operations.calls, ["show", "leave", "raw-off"]);
        assert_eq!(state, RestorationState::default());
    }

    #[test]
    fn restoration_attempts_every_step_after_an_earlier_error() {
        let mut state = RestorationState {
            raw_mode: true,
            alternate_screen: true,
            cursor_hidden: true,
        };
        let mut operations = RecordingOps {
            fail_show: true,
            ..RecordingOps::default()
        };

        let error = restore_with(&mut state, &mut operations).expect_err("show failure");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(operations.calls, ["show", "leave", "raw-off"]);
        assert!(state.cursor_hidden);
        assert!(!state.alternate_screen);
        assert!(!state.raw_mode);
    }
}
