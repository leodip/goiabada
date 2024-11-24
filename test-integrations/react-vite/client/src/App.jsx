import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ProtectedRoute } from './components/ProtectedRoute'
import Layout from './components/Layout'
import Home from './pages/Home'
import Protected from './pages/Protected'
import ManagersOnly from './pages/ManagersOnly'
import Callback from './pages/Callback'
import './styles/global.css'

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
              <ProtectedRoute requiredRole="manager">
                <ManagersOnly />
              </ProtectedRoute>
            } />
          </Route>
          <Route path="/callback" element={<Callback />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}

export default App