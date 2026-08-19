import { useEffect, useState } from 'react';
import { Users, ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../config/auth';
import './UsersList.css';

const API_BASE_URL = import.meta.env.VITE_API_URL;

const UsersList = () => {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const res = await apiClient.get(`${API_BASE_URL}/api/users`);
                if (res.ok) {
                    const data = await res.json();
                    // Filtrar solo los usuarios activos
                    setUsers(data.filter(u => u.active === true));
                }
            } catch (error) {
                console.error('Error al cargar usuarios:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchUsers();
    }, []);

    return (
        <div className="users-list-container">
            <div className="users-list-content">
                <div className="users-list-header">
                    <div className="users-list-title-row">
                        <Users className="users-list-icon" />
                        <div>
                            <h2>Lista de Usuarios Activos</h2>
                            <p>Usuarios aprobados y sus agentes asignados.</p>
                        </div>
                    </div>
                    <button className="back-btn" onClick={() => navigate('/settings')}>
                        <ArrowLeft size={16} /> Volver a Ajustes
                    </button>
                </div>

                {loading ? (
                    <div className="users-list-loading">
                        <div className="spinner"></div>
                        <p>Cargando usuarios...</p>
                    </div>
                ) : users.length === 0 ? (
                    <p className="empty-msg">No hay usuarios activos registrados.</p>
                ) : (
                    <table className="users-table">
                        <thead>
                            <tr>
                                <th>Nombre Completo</th>
                                <th>Email</th>
                                <th>Rol</th>
                                <th>Agente Asignado</th>
                            </tr>
                        </thead>
                        <tbody>
                            {users.map(u => (
                                <tr key={u.id}>
                                    <td className="user-name-cell">
                                        {`${u.firstName} ${u.paternalLastName} ${u.maternalLastName}`}
                                    </td>
                                    <td className="user-email-cell">{u.email}</td>
                                    <td>
                                        <span className={`role-badge ${u.role === 'ADMIN' ? 'role-admin' : 'role-user'}`}>
                                            {u.role}
                                        </span>
                                    </td>
                                    <td className="agent-cell">
                                        {u.assignedAgentName || <span className="no-agent">Sin asignar</span>}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
};

export default UsersList;
