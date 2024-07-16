import RemoveRedEyeIcon from '@mui/icons-material/RemoveRedEye';
import CreateIcon from '@mui/icons-material/Create';
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useEffect } from 'react';
import { toast } from 'react-toastify';

const Employee = () => {
    const { EntryData, getUserData, user, logout, UserExists, isExist } = useAuth();
    const navigate = useNavigate();

    const deleteuser = async (id) => {
        try {
            const res = await fetch(`${process.env.REACT_APP_API_URL}/deleteuser/${id}`, {
                method: "DELETE",
                headers: {
                    "Content-Type": "application/json",
                    "authorization": `${localStorage.getItem('user')}`
                },
            });
            if (!res.ok) {
                throw new Error('Error deleting user');
            }
            toast.warning("Data deleted");
            EntryData();
        } catch (error) {
            toast.error("Error deleting user");
        }
    };

    useEffect(() => {
        UserExists(user.id)
        if (!isExist) {
            logout();
            
        }
    }, [user.id, isExist, logout, UserExists]); 

    useEffect(() => {
        if (isExist) { 
            EntryData();
        }
    }, []);

    return (
        <>
            <div className="mt-5">
                <div className="container">
                    <div className="add_btn mt-2 mb-2">
                        <Link className="btn btn-primary" to='/register'>Add data</Link>
                    </div>
                    <table className="table table-striped">
                        <thead>
                            <tr key={1} className="table-dark">
                                <th scope="col">id</th>
                                <th scope="col">Username</th>
                                <th scope="col">Email</th>
                                <th scope="col">Job</th>
                                <th scope="col">Number</th>
                                <th scope="col"></th>
                            </tr>
                        </thead>
                        <tbody>
                            {getUserData.map((user, id) => (
                                <tr key={id}>
                                    <th scope="row">{id + 1}</th>
                                    <td>{user.name}</td>
                                    <td>{user.email}</td>
                                    <td>{user.work}</td>
                                    <td>{user.mobile}</td>
                                    <td className="d-flex justify-content-between">
                                        <Link to={`/view/:${user._id}`}><button className="btn btn-success"><RemoveRedEyeIcon /></button></Link>
                                        <Link to={`/edit/:${user._id}`}><button className="btn btn-primary"><CreateIcon /></button></Link>
                                        <button className="btn btn-danger" onClick={() => deleteuser(user._id)}><DeleteOutlineIcon /></button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </>
    );
}

export default Employee;
