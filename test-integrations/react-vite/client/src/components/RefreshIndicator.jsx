import { useAuth } from '../context/AuthContext';

const RefreshIndicator = () => {
    const { isRefreshing } = useAuth();

    if (!isRefreshing) return null;

    return (
        <div className="refresh-indicator">
            <div className="refresh-spinner"></div>
            <span>Refreshing tokens...</span>
        </div>
    );
};

export default RefreshIndicator;
