import { useState, useContext, createContext } from 'react';
import * as UserService from '../Services/UserService';
import { toast } from 'react-toastify';
const AuthContext = createContext(null);
export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(UserService.getUser());
    const [userAll, setUserAll] = useState(null);
    const [isExist, setExist] = useState(true);
    const [email,setEmail]=useState('');
    const [getUserData, setUserData] = useState([]);

    const login = async (email, password) => {
        try {
            const User = await UserService.login(email, password);
            toast.success('Login Successfully');

            setUser(User);
            setEmail('')
            return true;
        }
        catch (err) {
            toast.error(err.response.data);
            return false;
        }
    };
    const forgotPassword = async (email) => {
        try {
            await UserService.forgotPassword(email);
            toast.success("Password reset link sent to your email");
            return true;
        }
        catch (err) {
            toast.error(err.response.data);
            return false;
        }
    }
    const registerUser = async (RegisterData) => {
        try {
            const User = await UserService.register(RegisterData);
            toast.success("Verification otp send to Email");
            setEmail(User.email);
            return true;


        }
        catch (err) {
            toast.error(err.response.data);
            return false;

        }
    }
    const ResetPassword = async (password, token) => {
        try{
            const User = await UserService.resetPassword(password, token);
            setUser(User);
            console.log(user);
            toast.success("Password Reset Successfully");
            return true;

        }
        catch(err){
            toast.error(err.response.data);
            return false;
        }
    }

    const VerifyUser = async (email,otp) => {
        try {
            const User = await UserService.VerifyUser(email,otp);
            toast.success("User Verified");
            setUser(User);
            return true;
        }
        catch (err) {
            toast.error(err.response.data);
            return false;
        }
    }

    const ResendOTP = async (email) => {
        try {
             await UserService.resendOTP(email);
            toast.success("OTP send to Email");
            return true;
        }
        catch (err) {
            toast.error(err.response.data);
            return false;
        }
    }
    const EntryData = async () => {
        try {
            const data = await UserService.getdata();

            setUserData(data);


        }
        catch (err) {
            toast.error(err.response.data);
        }
    }

    const adminData = async () => {
        try {
            const Users = await UserService.getAdminData();
            toast.success("Employee Data fetched");
            setUserAll(Users);

        }
        catch (err) {
            toast.error(err.response.data);
        }
    }
    const DeleteEmployee = async (id) => {
        try {
             await UserService.DeleteEmployee(id);
            toast.warn("Employee deleted");
            setUserAll(prevUserAll => prevUserAll.filter(user => user.id !== id));
            EntryData();

        }
        catch (err) {
            toast.error(err.response.data);

        }
    }

    const UserExists = async (id) => {
        try {
            const checkUserExist = await UserService.UserExist(id);
            setExist(checkUserExist);
        }
        catch (err) {
            toast.error(err.response.data);
            return true;
        }
    }

    const updateUser = async (UpdateUser) => {
        try {
            const User = await UserService.updateProfile(UpdateUser);
            setUser(User);
            toast.success('User Profile updated');
            return true
        }
        catch (err) {
            toast.error(err.response.data);
            return false;
        }
    }
    const logout = () => {
        UserService.logout();
        setUser(null);
        setEmail('');
        toast.success("Logout SuccessFully");
    }
    return (
        <AuthContext.Provider
            value={
                { user, setUser, login, registerUser, logout, updateUser, userAll, setUserAll, adminData, EntryData, getUserData, setUserData, DeleteEmployee,UserExists,isExist,email,setEmail,VerifyUser ,ResendOTP,forgotPassword,ResetPassword}
            }
        >
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);