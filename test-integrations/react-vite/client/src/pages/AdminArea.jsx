import { useAuth } from '../context/AuthContext';
import { protectedApi } from '../api';
import ApiCallDemo from '../components/ApiCallDemo';

const AdminArea = () => {
    const { userInfo, tokens } = useAuth();

    // Get the scope from the access token
    const accessTokenScope = tokens?.access_token?.payload?.scope || '';
    const scopes = accessTokenScope.split(' ').filter(Boolean);

    return (
        <div className="page admin-page">
            <div className="page-header">
                <h1>Admin area</h1>
                <p className="page-description">
                    This page requires authentication and the &apos;backend:admin&apos; scope.
                </p>
            </div>

            <div className="access-info">
                <div className="access-badge admin">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 2L2 7l10 5 10-5-10-5z" />
                        <path d="M2 17l10 5 10-5" />
                        <path d="M2 12l10 5 10-5" />
                    </svg>
                    <span>Admin scope verified</span>
                </div>
            </div>

            <div className="welcome-section">
                <h2>Hello, {userInfo?.name || userInfo?.email || 'Admin'}!</h2>
                <p>
                    You have access to this area because your access token includes the
                    required &apos;backend:admin&apos; scope.
                </p>
            </div>

            <div className="api-demos">
                <h2>Admin API demonstrations</h2>
                <p className="section-description">
                    Test calling API endpoints that require admin scope.
                </p>

                <div className="api-demo-grid">
                    <ApiCallDemo
                        title="Admin info endpoint"
                        description="Calls /api/admin/info - requires 'backend:admin' scope"
                        apiCall={protectedApi.getAdminInfo}
                        buttonText="Get admin info"
                    />
                </div>
            </div>

            <div className="explanation-section">
                <h2>How this works</h2>
                <div className="explanation-content">
                    <p>
                        Access to this page is controlled by checking the access token&apos;s scope:
                    </p>
                    <ol>
                        <li>
                            <strong>Client-side route protection:</strong> The <code>ProtectedRoute</code>
                            component checks if the access token&apos;s scope includes &apos;backend:admin&apos;
                            before rendering this page.
                        </li>
                        <li>
                            <strong>Server-side API protection:</strong> The <code>/api/admin/*</code>
                            endpoints use the <code>hasRequiredScope(&apos;backend:admin&apos;)</code> middleware to
                            verify the scope from the access token.
                        </li>
                    </ol>
                    <p>
                        Scopes are different from groups - they define what actions the token is authorized
                        to perform, regardless of user group membership.
                    </p>
                </div>
            </div>

            {scopes.length > 0 && (
                <div className="groups-display">
                    <h3>Your scopes</h3>
                    <div className="groups-list">
                        {scopes.map(s => (
                            <span
                                key={s}
                                className={`badge ${s === 'backend:admin' ? 'highlight' : ''}`}
                            >
                                {s}
                            </span>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default AdminArea;
