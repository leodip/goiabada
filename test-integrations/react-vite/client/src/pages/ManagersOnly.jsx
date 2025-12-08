import { useAuth } from '../context/AuthContext';
import { protectedApi } from '../api';
import ApiCallDemo from '../components/ApiCallDemo';

const ManagersOnly = () => {
    const { userInfo } = useAuth();

    return (
        <div className="page managers-page">
            <div className="page-header">
                <h1>Managers area</h1>
                <p className="page-description">
                    This page requires both authentication and membership in the &apos;managers&apos; group.
                </p>
            </div>

            <div className="access-info">
                <div className="access-badge manager">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        <path d="M9 12l2 2 4-4" />
                    </svg>
                    <span>Manager access verified</span>
                </div>
            </div>

            <div className="welcome-section">
                <h2>Hello, {userInfo?.name || userInfo?.email || 'Manager'}!</h2>
                <p>
                    You have access to this restricted area because you are a member of the
                    manager group.
                </p>
            </div>

            <div className="api-demos">
                <h2>Manager API demonstrations</h2>
                <p className="section-description">
                    Test calling API endpoints that require manager privileges.
                </p>

                <div className="api-demo-grid">
                    <ApiCallDemo
                        title="Managers time endpoint"
                        description="Calls /api/managers/time - requires 'managers' group membership"
                        apiCall={protectedApi.getManagersTime}
                        buttonText="Get manager data"
                    />
                </div>
            </div>

            <div className="explanation-section">
                <h2>How this works</h2>
                <div className="explanation-content">
                    <p>
                        Access to this page is controlled by two mechanisms:
                    </p>
                    <ol>
                        <li>
                            <strong>Client-side route protection:</strong> The <code>ProtectedRoute</code>
                            component checks if the user&apos;s groups include &apos;managers&apos; before rendering
                            this page.
                        </li>
                        <li>
                            <strong>Server-side API protection:</strong> The <code>/api/managers/*</code>
                            endpoints use the <code>hasRequiredRole(&apos;managers&apos;)</code> middleware to
                            verify group membership from the ID token.
                        </li>
                    </ol>
                    <p>
                        This dual-layer protection ensures security even if client-side checks are bypassed.
                    </p>
                </div>
            </div>

            {userInfo?.groups && (
                <div className="groups-display">
                    <h3>Your groups</h3>
                    <div className="groups-list">
                        {userInfo.groups.map(g => (
                            <span
                                key={g}
                                className={`badge ${g === 'managers' ? 'highlight' : ''}`}
                            >
                                {g}
                            </span>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ManagersOnly;
