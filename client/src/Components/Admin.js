import { useEffect, useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import DefaultProfile from '../Images/Profile.png';
import { MdDelete } from "react-icons/md";
const Admin = () => {
    const { userAll, adminData, EntryData, getUserData,DeleteEmployee } = useAuth();
    const [selectedEmployee, setSelectedEmployee] = useState(null);

    useEffect(() => {
        EntryData();
        adminData();
    }, []);

    const handleProfileClick = (employee) => {
        setSelectedEmployee(employee);
    };

    const handleClosePopup = () => {
        setSelectedEmployee(null);
    };
    const handleDeleteEmployee = async (id) => {
        if (window.confirm("Are you sure you want to delete this employee?")) {
            await DeleteEmployee(id);
            adminData(); 
        }
    };
    return (
        <div className="admin-container">
            <h1 className="admin-title">Employee List</h1>
            <table className="admin-table">
                <thead>
                    <tr>
                        <th className="admin-column">Name</th>
                        <th className="admin-column">Email</th>
                        <th className="admin-column">Profile</th>
                        <th className="admin-column">Last Login</th>
                        <th className="admin-column">Delete</th>
                    </tr>
                </thead>
                <tbody>
                    {userAll && userAll.map((employee) => (
                        <tr key={employee._id}>
                            <td className="admin-cell">{employee.name}</td>
                            <td className="admin-cell">{employee.email}</td>
                            <td className="admin-cell">
                                <div className="employee-profile" onClick={() => handleProfileClick(employee)}>
                                    <img className='employee_admin-profile' src={employee.imageURL ? `${employee.imageURL}` : DefaultProfile} alt='profile' />
                                </div>
                            </td>
                            <td className="admin-cell">{employee.lastLogin ? new Date(employee.lastLogin).toLocaleString() : '-'}</td>
                            <td className="admin-cell">
                                <MdDelete onClick={() => handleDeleteEmployee(employee._id)} />
                            </td>
                            
                        </tr>
                    ))}
                </tbody>
            </table>
            {selectedEmployee && (
                <div className="popup-overlay" onClick={handleClosePopup}>
                    <div className="popup-content" onClick={(e) => e.stopPropagation()}>
                        <h2 className="popup-title">Entries by {selectedEmployee.name}</h2>
                        <div className="entry-list">
                            {getUserData
                                .filter((entry) => entry.creator === selectedEmployee._id)
                                .map((entry, index) => (
                                    <div key={index} className="entry-item">
                                        <p><strong>Entry {index + 1}:</strong></p>
                                        <p><strong>Name:</strong> {entry.name}</p>
                                        <p><strong>Email:</strong> {entry.email}</p>
                                        <p><strong>Work:</strong> {entry.work}</p>
                                        <p><strong>Description:</strong> {entry.desc}</p>
                                        <p><strong>Mobile:</strong> {entry.mobile}</p>
                                        <p><strong>Address:</strong> {entry.add}</p>
                                        <p><strong>AddedAt:</strong> {entry.AddedAt ? new Date(entry.AddedAt).toLocaleString() : '-'}</p>
                                        <p><strong>EditedAt:</strong> {entry.EditedAt ? new Date(entry.EditedAt).toLocaleString() : '-'}</p>
                                    </div>
                                ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Admin;
