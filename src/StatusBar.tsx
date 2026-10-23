import { Shield, MousePointer2, Keyboard, Cpu } from 'lucide-react';

interface Props {
  protectionOn: boolean;
  cursorActive: boolean;
  cursorShortcutEnabled: boolean;
  helperConnected: boolean;
  shortcutKey: string;
}

export default function StatusBar({
  protectionOn,
  cursorActive,
  cursorShortcutEnabled,
  helperConnected,
  shortcutKey,
}: Props) {
  return (
    <header className="status-bar">
      <div className="status-bar-left">
        <div className="status-indicator">
          <span className={`status-dot ${protectionOn ? '' : 'off'}`} />
          <Shield size={12} />
          <span>Protection {protectionOn ? 'ON' : 'OFF'}</span>
        </div>

        <div className="status-indicator">
          <span className={`status-dot ${helperConnected ? '' : 'off'}`} />
          <Cpu size={12} />
          <span>Windows Helper {helperConnected ? 'Connected' : 'Active (Simulated)'}</span>
        </div>

        <div className="status-indicator">
          <span className={`status-dot ${cursorActive ? 'cursor-active' : 'off'}`} />
          <MousePointer2 size={12} />
          <span>Cursor {cursorActive ? 'Active (Inspecting)' : 'Idle'}</span>
        </div>
      </div>

      <div className="status-bar-right">
        {cursorShortcutEnabled && protectionOn && (
          <div className="status-indicator">
            <Keyboard size={12} />
            <span>
              Hold{' '}
              <kbd
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  minWidth: 18,
                  padding: '0 4px',
                  height: 18,
                  background: '#24262c',
                  border: '1px solid #33363e',
                  borderRadius: 3,
                  fontSize: 10,
                  fontWeight: 600,
                  marginLeft: 2,
                  marginRight: 2,
                  color: 'var(--red)',
                }}
              >
                {shortcutKey || '5'}
              </kbd>{' '}
              to inspect
            </span>
          </div>
        )}
      </div>
    </header>
  );
}
