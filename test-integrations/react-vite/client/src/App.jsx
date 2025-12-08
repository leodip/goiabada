import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import Layout from './components/Layout';
import Home from './pages/Home';
import Protected from './pages/Protected';
import ManagersOnly from './pages/ManagersOnly';
import AdminArea from './pages/AdminArea';
import Tokens from './pages/Tokens';
import Callback from './pages/Callback';
import './styles/global.css';

function App() {
    return (
        <AuthProvider>
            <BrowserRouter>
                <Routes>
                    <Route path="/" element={<Layout />}>
                        <Route index element={<Home />} />
                        <Route path="protected" element={
                            <ProtectedRoute>
                                <Protected />
                            </ProtectedRoute>
                        } />
                        <Route path="managers" element={
                            <ProtectedRoute requiredRole="managers">
                                <ManagersOnly />
                            </ProtectedRoute>
                        } />
                        <Route path="admin" element={
                            <ProtectedRoute requiredScope="backend:admin">
                                <AdminArea />
                            </ProtectedRoute>
                        } />
                        <Route path="tokens" element={
                            <ProtectedRoute>
                                <Tokens />
                            </ProtectedRoute>
                        } />
                    </Route>
                    <Route path="/callback" element={<Callback />} />
                </Routes>
            </BrowserRouter>
        </AuthProvider>
    );
}

export default App;
