import React, { useId } from 'react';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';

interface FieldHelpProps {
  children: React.ReactNode;
  /**
   * Stable UI-test selector for this instance's button. Every `FieldHelp`
   * otherwise renders an indistinguishable "More information" control, so
   * panels with several fields have no way to target one specifically —
   * pass a field-specific id at each call site, e.g.
   * `"field-help-access-point-listen-address"`.
   */
  testId?: string;
  /** Overrides the default "More information" aria-label with field-specific context, e.g. `"About Listen Address"`. */
  ariaLabel?: string;
}

/**
 * Small "?" icon that reveals a field's fuller explanation in a tooltip on
 * hover/focus. Keeps the field label free of a permanent paragraph — only a
 * short always-visible format hint or hard-consequence warning should ever
 * sit under a field as plain text; everything else belongs here.
 */
const POPPER_CONFIG = {
  modifiers: [
    // Keeps the tooltip fully on-screen: flips to whichever side actually
    // has room, and nudges it inward if even the flipped side is tight
    // (e.g. a field near the edge of a narrow config drawer/panel).
    { name: 'flip', options: { fallbackPlacements: ['left', 'top', 'bottom', 'right'] } },
    { name: 'preventOverflow', options: { boundary: 'clippingParents', padding: 8 } },
  ],
};

const FieldHelp: React.FC<FieldHelpProps> = ({
  children,
  testId,
  ariaLabel = 'More information',
}) => {
  const tooltipId = useId();
  return (
    <OverlayTrigger
      placement="auto"
      popperConfig={POPPER_CONFIG}
      overlay={
        <Tooltip id={tooltipId} className="field-help-tooltip">
          {children}
        </Tooltip>
      }
    >
      <button type="button" className="field-help-icon" aria-label={ariaLabel} data-testid={testId}>
        <i className="fas fa-question-circle" aria-hidden="true" />
      </button>
    </OverlayTrigger>
  );
};

export default FieldHelp;
