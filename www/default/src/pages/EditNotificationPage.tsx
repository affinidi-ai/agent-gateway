import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { DeleteButton } from '../components/shared/DeleteButton';
import { useSaveAction } from '../hooks/useSaveAction';

interface NotificationForm {
  title: string;
  message: string;
  status: 'new' | 'read' | 'deleted';
}

const EditNotificationPage: React.FC = () => {
  const { run, saving, navigate } = useSaveAction();
  const { id } = useParams<{ id: string }>();
  const isEditMode = id !== 'new';

  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState<NotificationForm>({
    title: '',
    message: '',
    status: 'new',
  });
  const [error, setError] = useState<string>('');

  useEffect(() => {
    if (isEditMode) {
      fetchNotification();
    }
  }, [id]);

  const fetchNotification = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/notifications/${id}`);
      setForm({
        title: response.data.title,
        message: response.data.message,
        status: response.data.status,
      });
    } catch (error: any) {
      setError(error.message || 'Failed to load notification');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!form.title || !form.message) {
      setError('Title and message are required');
      return;
    }

    await run(
      () =>
        isEditMode
          ? apiClient.put(`/notifications/${id}`, form)
          : apiClient.post('/notifications', form),
      {
        successMessage: isEditMode ? 'Notification updated!' : 'Notification created!',
        redirectTo: '/notifications',
        onError: setError,
        errorMessage: 'Failed to save notification',
      }
    );
  };

  const handleDelete = async () => {
    await run(() => apiClient.delete(`/notifications/${id}`), {
      successMessage: 'Notification deleted!',
      redirectTo: '/notifications',
      onError: setError,
      errorMessage: 'Failed to delete notification',
    });
  };

  // Add keyboard shortcut support for save (Ctrl+S / Cmd+S)
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      // Check for Ctrl+S (Windows/Linux) or Cmd+S (Mac)
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault(); // Prevent browser's default save behavior

        // Only trigger save if not currently saving and form is valid
        if (!saving && form.title && form.message) {
          handleSubmit(event as any);
        }
      }
    };

    // Add event listener when component mounts
    document.addEventListener('keydown', handleKeyboardSave);

    // Cleanup: remove event listener when component unmounts
    return () => {
      document.removeEventListener('keydown', handleKeyboardSave);
    };
  }, [saving, form.title, form.message]);

  if (loading) {
    return (
      <div className="container mt-4">
        <div className="text-center py-4">
          <div className="spinner-border" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/notifications')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className={`fas fa-${isEditMode ? 'edit' : 'plus'}`}></i>{' '}
            {isEditMode ? `Edit Notification: ${form.title}` : 'Create New Notification'}
            {isEditMode && (
              <span
                className={`badge ms-2 ${
                  form.status === 'new'
                    ? 'text-bg-primary'
                    : form.status === 'read'
                      ? 'text-bg-secondary'
                      : 'text-bg-danger'
                }`}
              >
                {form.status.toUpperCase()}
              </span>
            )}
          </h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label htmlFor="title" className="form-label">
                Title *
              </label>
              <input
                type="text"
                className="form-control"
                id="title"
                value={form.title}
                onChange={e => setForm({ ...form, title: e.target.value })}
                required
                autoFocus={!isEditMode}
              />
            </div>
            <div className="mb-3">
              <label htmlFor="message" className="form-label">
                Message *
              </label>
              <textarea
                className="form-control"
                id="message"
                rows={5}
                value={form.message}
                onChange={e => setForm({ ...form, message: e.target.value })}
                required
              />
            </div>
            {isEditMode && (
              <div className="mb-4">
                <label className="form-label">Status</label>
                <div>
                  <div className="form-check form-check-inline">
                    <input
                      type="radio"
                      className="form-check-input"
                      id="status-new"
                      name="status"
                      checked={form.status === 'new'}
                      onChange={() => setForm({ ...form, status: 'new' })}
                    />
                    <label className="form-check-label" htmlFor="status-new">
                      <span className="badge text-bg-primary">NEW</span>
                    </label>
                  </div>
                  <div className="form-check form-check-inline">
                    <input
                      type="radio"
                      className="form-check-input"
                      id="status-read"
                      name="status"
                      checked={form.status === 'read'}
                      onChange={() => setForm({ ...form, status: 'read' })}
                    />
                    <label className="form-check-label" htmlFor="status-read">
                      <span className="badge text-bg-secondary">READ</span>
                    </label>
                  </div>
                </div>
              </div>
            )}
            <div className="d-flex gap-2">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    {isEditMode ? 'Saving...' : 'Creating...'}
                  </>
                ) : (
                  <>
                    <i className={`fas fa-${isEditMode ? 'save' : 'plus'} me-2`}></i>
                    {isEditMode ? ' Save' : ' Create'}
                  </>
                )}
              </button>
              {isEditMode && (
                <DeleteButton onDelete={handleDelete} disabled={saving} variant="danger">
                  Delete
                </DeleteButton>
              )}
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate('/notifications')}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditNotificationPage;
