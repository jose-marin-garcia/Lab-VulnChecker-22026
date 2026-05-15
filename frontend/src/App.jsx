import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Navbar from './components/Navbar/Navbar';
import { apiClient } from './config/auth';
import Login from './components/Login/Login';
import Register from './components/Login/Register';
import Home from './components/Home/Home';
import Settings from './components/Settings/Settings';
import Consumer from './components/Consumer/Consumer';
import Tables from './components/Tables/Tables';
import Summary from './components/Summary/Summary';
import Charts from './components/Charts/Charts';
import Evolution from './components/Evolution/Evolution';
import './App.css';

const API_BASE_URL = import.meta.env.VITE_API_URL;

// Componente para proteger rutas
const ProtectedRoute = ({ children, adminOnly = false }) => {
    const isAuthenticated = localStorage.getItem('is_authenticated') === 'true';
    const userRole = localStorage.getItem('user_role');
    const [checking, setChecking] = useState(true);
    const [valid, setValid] = useState(false);

    useEffect(() => {
        const validate = async () => {
            const token = localStorage.getItem('token');
            if (!token) {
                setValid(false);
                setChecking(false);
                return;
            }
            try {
                const res = await apiClient.get(`${API_BASE_URL}/api/users/me`);
                if (res.ok) {
                    const data = await res.json();
                    localStorage.setItem('user_role', data.role);
                    localStorage.setItem('user_name', data.firstName);
                    setValid(true);
                } else {
                    localStorage.clear();
                    setValid(false);
                }
            } catch {
                setValid(true);
            }
            setChecking(false);
        };
        validate();
    }, []);

    if (checking) return null;

    if (!isAuthenticated || !valid) {
        return <Navigate to="/" replace />;
    }

    if (adminOnly && userRole !== 'ADMIN') {
        return <Navigate to="/home" replace />;
    }

    return children;
};

const AppContent = () => {
    const location = useLocation(); // <--- Ahora sí funcionará porque lo importamos arriba
    const isPublicPage = location.pathname === '/' || location.pathname === '/register';

    return (
        <>
            {/* Si NO estamos en una página pública, mostramos la Navbar */}
            {!isPublicPage && <Navbar />}
            
            <Routes>
                <Route path="/" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route 
                    path="/home" 
                    element={<ProtectedRoute><Home /></ProtectedRoute>} 
                />
                <Route 
                    path="/settings" 
                    element={<ProtectedRoute adminOnly={true}><Settings /></ProtectedRoute>} 
                />
                <Route 
                    path="/consumer" 
                    element={<ProtectedRoute adminOnly={true}><Consumer /></ProtectedRoute>} 
                />
                <Route
                    path="/tables"
                    element={<ProtectedRoute><Tables /></ProtectedRoute>}
                />
                <Route
                    path="/critical"
                    element={
                        <ProtectedRoute>
                            <Tables
                                title="Vulnerabilidades Críticas"
                                subtitle="Vista priorizada de hallazgos críticos y altos."
                                defaultHighPriorityOnly={true}
                                lockHighPriority={true}
                                hideSeverityFilter={true}
                            />
                        </ProtectedRoute>
                    }
                />
                <Route
                    path="/summary"
                    element={<ProtectedRoute><Summary /></ProtectedRoute>}
                />
                <Route
                    path="/charts"
                    element={<ProtectedRoute><Charts /></ProtectedRoute>}
                />
                <Route
                    path="/evolution"
                    element={<ProtectedRoute><Evolution /></ProtectedRoute>}
                />
                <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
        </>
    );
};

function App() {
    return (
        <Router>
            <AppContent />
        </Router>
    );
}

export default App;
