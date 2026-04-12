use super::state::View;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    Advance,      // space/enter -- reveal next step or toggle detail
    ContinueAll,  // c -- reveal all remaining
    StepUp,       // up arrow
    StepDown,     // down arrow
    NextScenario, // j (selftest only)
    PrevScenario, // k (selftest only)
    Quit,         // q or ctrl-c
}

pub fn map_key(event: KeyEvent, view: View) -> Option<Action> {
    // Ctrl-C always quits
    if event.modifiers.contains(KeyModifiers::CONTROL) && event.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }
    match event.code {
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char(' ') | KeyCode::Enter => Some(Action::Advance),
        KeyCode::Char('c') => Some(Action::ContinueAll),
        KeyCode::Up => Some(Action::StepUp),
        KeyCode::Down => Some(Action::StepDown),
        KeyCode::Char('j') if view == View::Selftest => Some(Action::NextScenario),
        KeyCode::Char('k') if view == View::Selftest => Some(Action::PrevScenario),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }
    fn key_with_mod(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn space_maps_to_advance() {
        assert_eq!(
            map_key(key(KeyCode::Char(' ')), View::BundleVerify),
            Some(Action::Advance)
        );
    }
    #[test]
    fn enter_maps_to_advance() {
        assert_eq!(
            map_key(key(KeyCode::Enter), View::BundleVerify),
            Some(Action::Advance)
        );
    }
    #[test]
    fn c_maps_to_continue_all() {
        assert_eq!(
            map_key(key(KeyCode::Char('c')), View::BundleVerify),
            Some(Action::ContinueAll)
        );
    }
    #[test]
    fn q_maps_to_quit() {
        assert_eq!(
            map_key(key(KeyCode::Char('q')), View::BundleVerify),
            Some(Action::Quit)
        );
    }
    #[test]
    fn ctrl_c_maps_to_quit() {
        assert_eq!(
            map_key(
                key_with_mod(KeyCode::Char('c'), KeyModifiers::CONTROL),
                View::BundleVerify
            ),
            Some(Action::Quit)
        );
    }
    #[test]
    fn j_k_only_work_in_selftest() {
        assert_eq!(
            map_key(key(KeyCode::Char('j')), View::Selftest),
            Some(Action::NextScenario)
        );
        assert_eq!(
            map_key(key(KeyCode::Char('k')), View::Selftest),
            Some(Action::PrevScenario)
        );
        assert_eq!(map_key(key(KeyCode::Char('j')), View::BundleVerify), None);
        assert_eq!(map_key(key(KeyCode::Char('k')), View::BundleVerify), None);
    }
    #[test]
    fn arrows_map_to_step_cursor() {
        assert_eq!(
            map_key(key(KeyCode::Up), View::BundleVerify),
            Some(Action::StepUp)
        );
        assert_eq!(
            map_key(key(KeyCode::Down), View::BundleVerify),
            Some(Action::StepDown)
        );
    }
    #[test]
    fn unknown_key_returns_none() {
        assert_eq!(map_key(key(KeyCode::Char('x')), View::BundleVerify), None);
    }
}
