import { useAuth } from '../context/AuthContext';
import { protectedApi } from '../api';
import ApiCallDemo from '../components/ApiCallDemo';

const Protected = () => {
    const { userInfo } = useAuth();

    return (
        <div className="page protected-page">
            <div className="page-header">
                <h1>Protected page</h1>
                <p className="page-description">
                    This page is only accessible to authenticated users.
                </p>
            </div>

            <div className="welcome-section">
                <h2>Welcome, {userInfo?.name || userInfo?.email || 'User'}!</h2>
                <p>You have successfully authenticated and can access protected resources.</p>
            </div>

            <div className="api-demos">
                <h2>API demonstrations</h2>
                <p className="section-description">
                    Test calling protected API endpoints. These endpoints require a valid session.
                </p>

                <div className="api-demo-grid">
                    <ApiCallDemo
                        title="Protected time endpoint"
                        description="Calls /api/protected/time - requires authentication"
                        apiCall={protectedApi.getTime}
                        buttonText="Get server time"
                    />
                </div>
            </div>

            <div className="user-info-section">
                <h2>Your user info</h2>
                <p className="section-description">
                    Information from the UserInfo endpoint and ID token claims.
                </p>

                <div className="info-grid">
                    {userInfo?.sub && (
                        <div className="info-item">
                            <span className="info-label">Subject (sub)</span>
                            <span className="info-value">{userInfo.sub}</span>
                        </div>
                    )}
                    {userInfo?.email && (
                        <div className="info-item">
                            <span className="info-label">Email</span>
                            <span className="info-value">
                                {userInfo.email}
                                {userInfo.email_verified && (
                                    <span className="verified-badge" title="Email verified">
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                                            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
                                        </svg>
                                    </span>
                                )}
                            </span>
                        </div>
                    )}
                    {userInfo?.name && (
                        <div className="info-item">
                            <span className="info-label">Name</span>
                            <span className="info-value">{userInfo.name}</span>
                        </div>
                    )}
                    {userInfo?.groups && userInfo.groups.length > 0 && (
                        <div className="info-item">
                            <span className="info-label">Groups</span>
                            <span className="info-value">
                                {userInfo.groups.map(g => (
                                    <span key={g} className="badge">{g}</span>
                                ))}
                            </span>
                        </div>
                    )}
                </div>

                <div className="raw-data">
                    <h3>Raw user info</h3>
                    <pre>{JSON.stringify(userInfo, null, 2)}</pre>
                </div>
            </div>
        </div>
    );
};

export default Protected;
