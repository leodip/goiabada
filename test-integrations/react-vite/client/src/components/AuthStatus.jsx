import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import LoginDialog from './LoginDialog';

const AuthStatus = () => {
    const { isAuthenticated, isLoading, userInfo, logout } = useAuth();
    const [showLoginDialog, setShowLoginDialog] = useState(false);

    if (isLoading) {
        return (
            <div className="auth-status">
                <span className="loading-text">Loading...</span>
            </div>
        );
    }

    return (
        <>
            <div className="auth-status">
                {isAuthenticated && userInfo ? (
                    <div className="user-status">
                        <div className="user-avatar">
                            {userInfo.picture ? (
                                <img src={userInfo.picture} alt="Avatar" />
                            ) : (
                                <span>{(userInfo.name || userInfo.email || '?')[0].toUpperCase()}</span>
                            )}
                        </div>
                        <span className="user-email">{userInfo.email}</span>
                        <button onClick={() => logout()} className="btn btn-secondary btn-sm">
                            Logout
                        </button>
                    </div>
                ) : (
                    <div className="login-status">
                        <span className="not-logged-in">Not logged in</span>
                        <button
                            onClick={() => setShowLoginDialog(true)}
                            className="btn btn-primary btn-sm"
                        >
                            Sign In
                        </button>
                    </div>
                )}
            </div>

            <LoginDialog
                isOpen={showLoginDialog}
                onClose={() => setShowLoginDialog(false)}
            />
        </>
    );
};

export default AuthStatus;
