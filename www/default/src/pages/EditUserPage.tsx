import React, { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { formatDateTime } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import { useSaveAction } from '../hooks/useSaveAction';

interface User {
  username: string;
  user_id: string;
  role: 'administrator' | 'poweruser' | 'user';
  status: 'new' | 'approved' | 'disabled';
  is_primary?: boolean;
  created_at: string;
  updated_at: string;
  first_name?: string;
  last_name?: string;
  email?: string;
  department?: string;
  job_title?: string;
  avatar_path?: string;
}

interface UserForm {
  role: 'administrator' | 'poweruser' | 'user';
  status: 'new' | 'approved' | 'disabled';
  first_name: string;
  last_name: string;
  email: string;
  department: string;
  job_title: string;
}

const EditUserPage: React.FC = () => {
  const { run, saving, navigate } = useSaveAction();
  const { userId } = useParams<{ userId: string }>();

  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [form, setForm] = useState<UserForm>({
    role: 'user',
    status: 'new',
    first_name: '',
    last_name: '',
    email: '',
    department: '',
    job_title: '',
  });
  const [error, setError] = useState<string>('');
  const [created, setCreated] = useState<string>('');
  const [updated, setUpdated] = useState<string>('');

  const fetchUser = useCallback(async () => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/users/${userId}`);
      setUser(response.data);
      setForm({
        role: response.data.role,
        status: response.data.status,
        first_name: response.data.first_name || '',
        last_name: response.data.last_name || '',
        email: response.data.email || '',
        department: response.data.department || '',
        job_title: response.data.job_title || '',
      });
      setCreated(response.data.created_at);
      setUpdated(response.data.updated_at);
    } catch (error: any) {
      setError(error.message || 'Failed to load user');
    } finally {
      setLoading(false);
    }
  }, [userId]);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError('');
      await run(() => apiClient.put(`/users/${userId}`, form), {
        successMessage: 'User updated!',
        redirectTo: '/users',
        onError: setError,
        errorMessage: 'Failed to update user',
      });
    },
    [form, run, userId]
  );

  useEffect(() => {
    if (userId) {
      fetchUser();
    }
  }, [fetchUser, userId]);

  // Keyboard shortcut for save (Ctrl+S or Cmd+S)
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if (!saving && userId) {
          handleSubmit(event as any);
        }
      }
    };

    document.addEventListener('keydown', handleKeyboardSave);
    return () => {
      document.removeEventListener('keydown', handleKeyboardSave);
    };
  }, [handleSubmit, saving, userId]);

  const handleDelete = async () => {
    await run(() => apiClient.delete(`/users/${userId}`), {
      successMessage: 'User deleted!',
      redirectTo: '/users',
      onError: setError,
      errorMessage: 'Failed to delete user',
    });
  };

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
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/users')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-user-edit"></i> Edit User: {user?.username || userId}
          </h6>
        </div>
        <div className="card-body">
          {error && (
            <div className="alert alert-danger" role="alert">
              {error}
            </div>
          )}
          {user?.is_primary && (
            <div className="alert alert-primary" role="alert">
              <i className="fas fa-crown me-2"></i>
              This is the primary administrator account. Role and status cannot be changed, and the
              account cannot be deleted.
            </div>
          )}
          {form.role === 'administrator' && !user?.is_primary && (
            <div className="alert alert-warning" role="alert">
              <i className="fas fa-exclamation-triangle me-2"></i>
              This user is an administrator and cannot be deleted or downgraded below power user.
            </div>
          )}
          {form.status === 'new' && (
            <div className="alert alert-info" role="alert">
              <i className="fas fa-info-circle me-2"></i>
              This user is new and awaiting approval. Set status to "Approved" to allow them to sign
              in.
            </div>
          )}
          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label className="form-label">Username</label>
              <input type="text" className="form-control" value={user?.username || ''} disabled />
            </div>
            {created && (
              <div className="row">
                <div className="col-md-6 mb-3">
                  <label className="form-label">Registered</label>
                  <input
                    type="text"
                    className="form-control"
                    value={formatDateTime(created)}
                    disabled
                  />
                </div>
                <div className="col-md-6 mb-3">
                  <label className="form-label">Last Updated</label>
                  <input
                    type="text"
                    className="form-control"
                    value={updated ? formatDateTime(updated) : 'N/A'}
                    disabled
                  />
                </div>
              </div>
            )}
            <div className="mb-3">
              <label className="form-label">Role</label>
              <select
                className="form-control dropdown-styling"
                value={form.role}
                onChange={e => setForm({ ...form, role: e.target.value as any })}
                disabled={user?.is_primary}
              >
                <option value="user">User</option>
                <option value="poweruser">Power User</option>
                <option value="administrator">Administrator</option>
              </select>
            </div>
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
                    disabled={user?.is_primary}
                  />
                  <label className="form-check-label" htmlFor="status-new">
                    <span className="badge text-bg-primary">NEW</span> - Awaiting approval
                  </label>
                </div>
                <div className="form-check form-check-inline">
                  <input
                    type="radio"
                    className="form-check-input"
                    id="status-approved"
                    name="status"
                    checked={form.status === 'approved'}
                    onChange={() => setForm({ ...form, status: 'approved' })}
                    disabled={user?.is_primary}
                  />
                  <label className="form-check-label" htmlFor="status-approved">
                    <span className="badge text-bg-success">APPROVED</span> - Can sign in
                  </label>
                </div>
                <div className="form-check form-check-inline">
                  <input
                    type="radio"
                    className="form-check-input"
                    id="status-disabled"
                    name="status"
                    checked={form.status === 'disabled'}
                    onChange={() => setForm({ ...form, status: 'disabled' })}
                    disabled={user?.is_primary}
                  />
                  <label className="form-check-label" htmlFor="status-disabled">
                    <span className="badge text-bg-secondary">DISABLED</span> - Cannot sign in
                  </label>
                </div>
              </div>
            </div>

            <hr className="my-4" />

            <h6 className="text-primary mb-3">
              <i className="fas fa-user-circle"></i> Profile Information
            </h6>

            <div className="row">
              <div className="col-md-6 mb-3">
                <label className="form-label">First Name</label>
                <input
                  type="text"
                  className="form-control"
                  value={form.first_name}
                  onChange={e => setForm({ ...form, first_name: e.target.value })}
                  placeholder="Enter first name"
                />
              </div>
              <div className="col-md-6 mb-3">
                <label className="form-label">Last Name</label>
                <input
                  type="text"
                  className="form-control"
                  value={form.last_name}
                  onChange={e => setForm({ ...form, last_name: e.target.value })}
                  placeholder="Enter last name"
                />
              </div>
            </div>

            <div className="mb-3">
              <label className="form-label">Email</label>
              <input
                type="email"
                className="form-control"
                value={form.email}
                onChange={e => setForm({ ...form, email: e.target.value })}
                placeholder="Enter email address"
              />
            </div>

            <div className="row">
              <div className="col-md-6 mb-3">
                <label className="form-label">Department</label>
                <input
                  type="text"
                  className="form-control"
                  value={form.department}
                  onChange={e => setForm({ ...form, department: e.target.value })}
                  placeholder="Enter department"
                />
              </div>
              <div className="col-md-6 mb-3">
                <label className="form-label">Job Title</label>
                <input
                  type="text"
                  className="form-control"
                  value={form.job_title}
                  onChange={e => setForm({ ...form, job_title: e.target.value })}
                  placeholder="Enter job title"
                />
              </div>
            </div>

            <div className="d-flex gap-2">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    Saving...
                  </>
                ) : (
                  <>
                    <i className="fas fa-save me-2"></i> Save
                  </>
                )}
              </button>
              {form.role !== 'administrator' && !user?.is_primary && (
                <DeleteButton onDelete={handleDelete} disabled={saving} variant="danger">
                  Delete User
                </DeleteButton>
              )}
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => navigate('/users')}
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

export default EditUserPage;
