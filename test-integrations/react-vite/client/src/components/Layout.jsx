import { Link, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import AuthStatus from './AuthStatus';
import RefreshIndicator from './RefreshIndicator';

const Layout = () => {
    const { isAuthenticated, userInfo, tokens } = useAuth();

    return (
        <div className="app-container">
            <RefreshIndicator />

            <header className="header">
                <div className="header-content">
                    <div className="logo">
                        <Link to="/">
                            <span className="logo-icon">G</span>
                            <span className="logo-text">Goiabada react-vite demo</span>
                        </Link>
                    </div>

                    <nav className="nav">
                        <div className="nav-links">
                            <Link to="/" className="nav-link">Home</Link>
                            {isAuthenticated && (
                                <>
                                    <Link to="/protected" className="nav-link">Protected</Link>
                                    {userInfo?.groups?.includes('managers') && (
                                        <Link to="/managers" className="nav-link">Managers</Link>
                                    )}
                                    {tokens?.access_token?.payload?.scope?.includes('backend:admin') && (
                                        <Link to="/admin" className="nav-link">Admin</Link>
                                    )}
                                    <Link to="/tokens" className="nav-link">Token inspector</Link>
                                </>
                            )}
                        </div>

                        <div className="nav-actions">
                            <AuthStatus />
                        </div>
                    </nav>
                </div>
            </header>

            <main className="main-content">
                <Outlet />
            </main>

            <footer className="footer">
                <p>                    
                    <a href="https://goiabada.dev" target="_blank" rel="noopener noreferrer">
                        Goiabada docs
                    </a>
                </p>
            </footer>
        </div>
    );
};

export default Layout;
