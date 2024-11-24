import { useAuth } from '../context/AuthContext';

const AuthStatus = () => {
  const { isAuthenticated, isLoading, userInfo, login, logout } = useAuth();

  if (isLoading) {
    return <div className="auth-status">Loading...</div>;
  }

  return (
    <div className="auth-status">
      {isAuthenticated && userInfo ? (
        <div className="user-info">
          <span>{userInfo.email}</span>
          <button onClick={logout} className="button">
            Logout
          </button>
        </div>
      ) : (
        <div>
          <span>Not logged in</span>
          <button onClick={login} className="button">
            Login
          </button>
        </div>
      )}
    </div>
  );
};

export default AuthStatus;