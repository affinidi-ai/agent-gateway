import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { apiClient } from '../api';
import { formatDateTime } from '../utils/stringUtils';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { DeleteButton } from '../components/shared/DeleteButton';
import SearchInput from '../components/shared/SearchInput';
import { UserAvatar } from '../components/shared/UserAvatar';
import { usePermissions } from '../context/PermissionsContext';

const ROLE_BADGE: Record<string, string> = {
  administrator: 'text-bg-danger',
  poweruser: 'text-bg-warning',
};

const STATUS_BADGE: Record<string, string> = {
  new: 'text-bg-primary',
  approved: 'text-bg-success',
  disabled: 'text-bg-secondary',
};

interface User {
  username: string;
  user_id: string;
  role: 'administrator' | 'poweruser' | 'user';
  status: 'new' | 'approved' | 'disabled';
  is_primary?: boolean;
  created_at: string;
  updated_at: string;
  last_logged_in?: string;
  first_name?: string;
  last_name?: string;
  email?: string;
  department?: string;
  job_title?: string;
  avatar_path?: string;
}

const UsersPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { hasPermission } = usePermissions();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | 'administrator' | 'poweruser' | 'user'>(
    'all'
  );
  const [statusFilter, setStatusFilter] = useState<'all' | 'new' | 'approved' | 'disabled'>('all');

  const fetchUsers = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.get('/users');
      setUsers(response.data);
    } catch (err: any) {
      setError(err.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchCurrentUser = useCallback(async () => {
    try {
      const response = await apiClient.get('/profile');
      setCurrentUserId(response.data.user_id);
    } catch (err: any) {
      console.error('Failed to fetch current user:', err);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
    fetchCurrentUser();
  }, [fetchUsers, fetchCurrentUser]);

  const handleQuickApprove = useCallback(
    async (user: User) => {
      try {
        await apiClient.put(`/users/${user.user_id}`, { status: 'approved' });
        setSuccess(`User '${user.username}' approved successfully`);
        setTimeout(() => setSuccess(null), 3000);
        fetchUsers();
      } catch (err: any) {
        setError(err.message || 'Failed to approve user');
      }
    },
    [fetchUsers]
  );

  const handleDelete = useCallback(
    async (user: User) => {
      try {
        await apiClient.delete(`/users/${user.user_id}`);
        setSuccess('User deleted successfully');
        setTimeout(() => setSuccess(null), 3000);
        fetchUsers();
      } catch (err: any) {
        setError(err.message || 'Failed to delete user');
      }
    },
    [fetchUsers]
  );

  const filteredUsers = useMemo(() => {
    const trimmedSearch = searchTerm.trim().toLowerCase();
    return users.filter(user => {
      if (trimmedSearch) {
        const matchesSearch =
          user.username?.toLowerCase().includes(trimmedSearch) ||
          user.first_name?.toLowerCase().includes(trimmedSearch) ||
          user.last_name?.toLowerCase().includes(trimmedSearch) ||
          user.email?.toLowerCase().includes(trimmedSearch) ||
          user.department?.toLowerCase().includes(trimmedSearch) ||
          user.job_title?.toLowerCase().includes(trimmedSearch);
        if (!matchesSearch) return false;
      }
      if (roleFilter !== 'all' && user.role !== roleFilter) return false;
      if (statusFilter !== 'all' && user.status !== statusFilter) return false;
      return true;
    });
  }, [users, searchTerm, roleFilter, statusFilter]);

  const showBadgePreview = useMemo(() => {
    const params = new URLSearchParams(location.search);
    return params.get('badgePreview') === '1';
  }, [location.search]);

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <SearchInput value={searchTerm} onChange={setSearchTerm} placeholder="Filter Users...." />
          <select
            className="form-control dropdown-styling"
            value={roleFilter}
            onChange={e => setRoleFilter(e.target.value as any)}
            style={{
              width: '160px',
              display: 'inline-block',
              marginLeft: '0.75rem',
            }}
          >
            <option value="all">All Roles</option>
            <option value="administrator">Administrator</option>
            <option value="poweruser">Power User</option>
            <option value="user">User</option>
          </select>
          <select
            className="form-control dropdown-styling"
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value as any)}
            style={{
              width: '160px',
              display: 'inline-block',
              marginLeft: '0.75rem',
            }}
          >
            <option value="all">All Statuses</option>
            <option value="new">New</option>
            <option value="approved">Approved</option>
            <option value="disabled">Disabled</option>
          </select>
        </div>
      </div>

      {showBadgePreview && (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-flask me-2"></i>
              Badge Style Preview (Option 1/2/3)
            </h6>
          </div>
          <div className="card-body">
            <div className="badge-preview-grid">
              <div className="badge-preview-option">
                <div className="badge-preview-title">Option 1: Soft Flat Counter</div>
                <div className="badge-preview-row">
                  <span className="badge-preview-label">User Management</span>
                  <span className="badge-preview-chip badge-preview-chip--soft">24 of 60</span>
                  <button className="btn btn-sm btn-primary" type="button">
                    Add User
                  </button>
                </div>
              </div>

              <div className="badge-preview-option">
                <div className="badge-preview-title">Option 2: Outline Micro-Chip</div>
                <div className="badge-preview-row">
                  <span className="badge-preview-label">User Management</span>
                  <span className="badge-preview-chip badge-preview-chip--outline">24 of 60</span>
                  <button className="btn btn-sm btn-primary" type="button">
                    Add User
                  </button>
                </div>
              </div>

              <div className="badge-preview-option">
                <div className="badge-preview-title">Option 3: Dot-Led Count Token</div>
                <div className="badge-preview-row">
                  <span className="badge-preview-label">User Management</span>
                  <span className="badge-preview-chip badge-preview-chip--dot">24 of 60</span>
                  <button className="btn btn-sm btn-primary" type="button">
                    Add User
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}
      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}

      {loading ? (
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '60vh',
          }}
        >
          <div className="spinner-border" role="status" style={{ color: 'rgba(0, 0, 0, 0.5)' }}>
            <span className="visually-hidden"></span>
          </div>
        </div>
      ) : users.length === 0 ? (
        <div className="card shadow mb-4">
          <div className="card-body text-center">
            <div className="text-muted">
              <i className="fas fa-users fa-3x mb-3"></i>
              <p>No users found.</p>
            </div>
          </div>
        </div>
      ) : (
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <div className="d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-users"></i> User Management
                <Badge
                  value={filteredUsers.length}
                  suffix={
                    searchTerm || roleFilter !== 'all' || statusFilter !== 'all'
                      ? ` of ${users.length}`
                      : undefined
                  }
                  className="ms-2"
                  ariaLabel={`${filteredUsers.length}${
                    searchTerm || roleFilter !== 'all' || statusFilter !== 'all'
                      ? ` of ${users.length}`
                      : ''
                  } users`}
                />
              </h6>
              <AppButton
                variant="primary"
                size="md"
                className="shadow-sm"
                onClick={() => navigate('/users/integrations')}
                iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
              >
                Add Integration
              </AppButton>
            </div>
          </div>
          <div className="card-body">
            <div className="table-responsive">
              <table className="table table-hover table-sm">
                <thead>
                  <tr>
                    <th>Avatar</th>
                    <th>Username</th>
                    <th>Name</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map(user => {
                    return (
                      <tr
                        key={user.user_id}
                        className={user.status === 'new' ? 'table-light' : ''}
                        onClick={() => setSelectedUser(user)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td>
                          <UserAvatar
                            avatarPath={user.avatar_path}
                            alt={user.username}
                            size="table"
                          />
                        </td>
                        <td>
                          <strong>{user.username}</strong>
                          {user.is_primary && (
                            <span
                              className="badge text-bg-primary ms-2"
                              style={{ marginLeft: '10px' }}
                              title="Primary Administrator"
                            >
                              <i className="fas fa-crown"></i> PRIMARY
                            </span>
                          )}
                          {user.status === 'new' && (
                            <span
                              className="badge text-bg-warning ms-2"
                              style={{ marginLeft: '10px' }}
                            >
                              NEEDS APPROVAL
                            </span>
                          )}
                          {currentUserId && user.user_id === currentUserId && (
                            <span
                              className="badge text-bg-info ms-2"
                              style={{ marginLeft: '10px' }}
                            >
                              YOU
                            </span>
                          )}
                        </td>
                        <td>
                          {user.first_name || user.last_name ? (
                            <span>
                              {user.first_name} {user.last_name}
                            </span>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                        <td>
                          <span className={`badge ${ROLE_BADGE[user.role] ?? 'text-bg-info'}`}>
                            {user.role.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <span
                            className={`badge ${STATUS_BADGE[user.status] ?? 'text-bg-secondary'}`}
                          >
                            {user.status.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <small>
                            {user.last_logged_in ? (
                              formatDateTime(user.last_logged_in, true)
                            ) : (
                              <span className="text-muted">Never</span>
                            )}
                          </small>
                        </td>
                        <td className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                          {hasPermission('users.edit') && (
                            <>
                              <button
                                className="btn btn-sm btn-primary"
                                onClick={() => navigate(`/users/${user.user_id}`)}
                                title="Edit user"
                              >
                                <i className="fas fa-edit"></i>
                              </button>
                            </>
                          )}
                          {hasPermission('users.approve') && user.status === 'new' && (
                            <>
                              <button
                                className="btn btn-sm btn-success"
                                onClick={() => handleQuickApprove(user)}
                                title="Quick approve user"
                              >
                                <i className="fas fa-check"></i> Approve
                              </button>
                            </>
                          )}
                          {hasPermission('users.delete') &&
                            user.role !== 'administrator' &&
                            !user.is_primary && (
                              <DeleteButton
                                onDelete={() => handleDelete(user)}
                                className="btn-sm"
                                title="Delete user permanently"
                              />
                            )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* User Details Modal */}
      {selectedUser && (
        <div
          className="modal fade show"
          style={{ display: 'block', backgroundColor: 'rgba(0,0,0,0.5)' }}
          onClick={() => setSelectedUser(null)}
        >
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  <i className="fas fa-user"></i> User Details - {selectedUser.username}
                </h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => setSelectedUser(null)}
                  aria-label="Close"
                />
              </div>
              <div className="modal-body">
                <div className="row mb-3">
                  <div className="col-md-4 text-center">
                    <UserAvatar
                      avatarPath={selectedUser.avatar_path}
                      alt={selectedUser.username}
                      size="modal"
                    />
                  </div>
                  <div className="col-md-8">
                    <div className="mb-2">
                      <strong>Name:</strong>{' '}
                      {selectedUser.first_name || selectedUser.last_name ? (
                        <span>
                          {selectedUser.first_name} {selectedUser.last_name}
                        </span>
                      ) : (
                        <span className="text-muted">Not provided</span>
                      )}
                    </div>
                    <div className="mb-2">
                      <strong>Email:</strong>{' '}
                      {selectedUser.email || <span className="text-muted">Not provided</span>}
                    </div>
                    <div className="mb-2">
                      <strong>Role:</strong>{' '}
                      <span className={`badge ${ROLE_BADGE[selectedUser.role] ?? 'text-bg-info'}`}>
                        {selectedUser.role.toUpperCase()}
                      </span>
                    </div>
                    <div className="mb-2">
                      <strong>Status:</strong>{' '}
                      <span
                        className={`badge ${STATUS_BADGE[selectedUser.status] ?? 'text-bg-secondary'}`}
                      >
                        {selectedUser.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                </div>

                <hr />

                <div className="mb-2">
                  <strong>Department:</strong>{' '}
                  {selectedUser.department || <span className="text-muted">Not provided</span>}
                </div>
                <div className="mb-2">
                  <strong>Job Title:</strong>{' '}
                  {selectedUser.job_title || <span className="text-muted">Not provided</span>}
                </div>

                <hr />

                <div className="mb-2">
                  <strong>Created:</strong>{' '}
                  <span className="text-muted">
                    {formatDateTime(selectedUser.created_at, true)}
                  </span>
                </div>
                <div className="mb-2">
                  <strong>Last Updated:</strong>{' '}
                  <span className="text-muted">
                    {formatDateTime(selectedUser.updated_at, true)}
                  </span>
                </div>
                <div className="mb-2">
                  <strong>Last Login:</strong>{' '}
                  {selectedUser.last_logged_in ? (
                    <span className="text-muted">
                      {formatDateTime(selectedUser.last_logged_in, true)}
                    </span>
                  ) : (
                    <span className="text-muted">Never</span>
                  )}
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setSelectedUser(null)}
                >
                  Close
                </button>
                {hasPermission('users.delete') && selectedUser.role !== 'administrator' && (
                  <DeleteButton
                    onDelete={() => {
                      handleDelete(selectedUser);
                      setSelectedUser(null);
                    }}
                    variant="danger"
                  >
                    Delete User
                  </DeleteButton>
                )}
                {hasPermission('users.edit') && (
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => {
                      navigate(`/users/${selectedUser.user_id}`);
                      setSelectedUser(null);
                    }}
                  >
                    <i className="fas fa-edit"></i> Edit User
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UsersPage;
