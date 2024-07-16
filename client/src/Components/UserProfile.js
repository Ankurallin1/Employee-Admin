import { useAuth } from '../hooks/useAuth';
import { useState } from 'react';
import { CiEdit } from "react-icons/ci";
import DefaultProfile from '../Images/Profile.png';
import { IoMdAddCircle } from "react-icons/io";
import { useNavigate } from 'react-router-dom';
import Unauthenticated from './Unauthenticated';
import { RxCross1 } from "react-icons/rx";
const UserProfile = () => {
    const { user, logout, updateUser } = useAuth();
    const [isEditingName, setIsEditingName] = useState(false);
    const [newName, setNewName] = useState(user?.name || '');
    const [image, setImage] = useState(null);
    const [preview, setPreview] = useState(false);
    const [previewImage,setPreviewImage]=useState(null);
    const navigate = useNavigate();

    const handleSaveChanges = async () => {
        const formData = new FormData();
        formData.append('name', newName);
        if (image) {
            formData.append('image', image);
        }
        setPreview(false);

        await updateUser(formData);

        setIsEditingName(false);
    };

    const handleLogOut = () => {
        logout();
        navigate('/login');
    };

    const handleImageUpload = (e) => {
        const file = e.target.files[0];
        setPreviewImage(URL.createObjectURL(file));
        setPreview(true);

        setImage(file);
    };

    if (!user) {
        return <Unauthenticated />;
    }

    return (
        <div className="profile_wrapper">
            <div className="profile_content">
                <div className="profile_image">
                    <img src={user.imageURL ? `${user.imageURL}` : DefaultProfile} alt='profile' />

                    <label htmlFor='file-upload'>
                        <IoMdAddCircle size={'25px'} style={{ cursor: 'pointer' }} />
                        <input id="file-upload" type="file" onChange={handleImageUpload} style={{ display: 'none' }} />
                    </label>
                </div>
                <div className="profile_info">
                    <div className="profile_name">
                        {isEditingName ? (
                            <input type="text" value={newName} onChange={(e) => setNewName(e.target.value)} />
                        ) : (
                            <>
                                <p>{user.name}</p>
                                <CiEdit className='edit' size={'20px'} style={{ margin: 'auto', cursor: 'pointer' }} onClick={() => setIsEditingName(true)} />
                            </>
                        )}
                    </div>
                    
                    {preview && (
                        <>
                            <RxCross1 style={{ cursor: 'pointer' }} onClick={() => setPreview(false)} />
                            <img className='previewImage' src={previewImage} alt='uploaded' />
                        </>
                    )}
                </div>
            </div>
            <button className='save' onClick={handleSaveChanges}>Save</button>
            <button className="logout_button" onClick={handleLogOut}>Log Out</button>
        </div>
    );
};

export default UserProfile;
