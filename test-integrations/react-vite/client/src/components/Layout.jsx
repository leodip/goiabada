import { Link, Outlet } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import AuthStatus from './AuthStatus'

const Layout = () => {
    const { isAuthenticated, userInfo } = useAuth();

    return (
        <div>
            <header className="header">
                <nav className="nav">
                    <div className="nav-links">
                        <Link to="/">Home</Link>
                        {isAuthenticated && (
                            <>
                                <Link to="/protected">Protected Page</Link>
                                {userInfo?.groups?.includes('manager') && (
                                    <Link to="/managers">Managers Only</Link>
                                )}
                            </>
                        )}
                    </div>
                    <AuthStatus />
                </nav>
            </header>
            <main className="main-content">
                <Outlet />
            </main>
        </div>
    )
}

export default Layout