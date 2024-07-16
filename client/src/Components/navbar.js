import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';
import DefaultProfile from '../Images/Profile.png';

const Navbar = () => {
    const { user } = useAuth();
    const navigate = useNavigate();

    const { logout } = useAuth();
    const handleLogOut = () => {
        logout();
        navigate('/login');
    }
    return (
        <header>
            <nav className="navbar navbar-expand-lg bg-body-tertiary">
                <div className="container-fluid">
                  
                    <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                        <span className="navbar-toggler-icon"></span>
                    </button>
                    <div className="collapse navbar-collapse" id="navbarSupportedContent">
                        <ul className="navbar-nav me-auto mb-2 mb-lg-0">
                            
                            <li className="nav-item">
                            {
                    user &&   <Link className="navbar-brand" to='/profile'><img className='nav_profile' src={user.imageURL ? `${user.imageURL}` : DefaultProfile} alt='profile' />{user.name}</Link>
                  }
                            </li>



                        </ul>
                        <button onClick={handleLogOut} className="btn btn-outline-success" >Log Out</button>

                    </div>
                </div>
            </nav>
        </header>
    )
}
export default Navbar;