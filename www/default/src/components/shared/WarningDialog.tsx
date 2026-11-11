import React from 'react';

interface WarningDialogProps {
  testId: string;
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  footer: React.ReactNode;
}

/**
 * A centred modal whose title carries a red warning icon, with a close button, a body and a
 * footer of actions, named by its title (element id `<testId>-title`).
 */
export const WarningDialog: React.FC<WarningDialogProps> = ({
  testId,
  title,
  onClose,
  children,
  footer,
}) => (
  <>
    <div
      className="modal fade show"
      style={{ display: 'block' }}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby={`${testId}-title`}
      data-testid={testId}
    >
      <div className="modal-dialog modal-dialog-centered">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id={`${testId}-title`}>
              <i className="fas fa-triangle-exclamation me-2 text-danger" aria-hidden="true" />
              {title}
            </h5>
            <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
          </div>
          <div className="modal-body">{children}</div>
          <div className="modal-footer">{footer}</div>
        </div>
      </div>
    </div>
    <div className="modal-backdrop fade show" />
  </>
);
