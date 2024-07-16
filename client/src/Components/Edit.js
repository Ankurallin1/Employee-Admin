import React, { useState, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import Unauthenticated from './Unauthenticated';

const Edit = () => {
    const Navigate = useNavigate();
    const [unauthenticated, setUnauthenticated] = useState(false);

    const [inpval, setINP] = useState({
        name: "",
        email: "",
        age: "",
        mobile: "",
        work: "",
        add: "",
        desc: ""
    })

    const setdata = (e) => {
        const { name, value } = e.target;
        setINP((preval) => {
            return {
                ...preval,
                [name]: value
            }
        })
    }

    let { id } = useParams("");
    id = id.substring(1);

    const getdata = async (e) => {
        const res = await fetch(`${process.env.REACT_APP_API_URL}/getuser/${id}`, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `${localStorage.getItem('user')}`
            },
        });

        if (res.status === 401)
            setUnauthenticated(true)
        else {
            const data = await res.json();

            if (res.status === 404 || !data) {
                alert("error");

            } else {
                setINP(data[0]);

            }
        }
    }
    useEffect(() => {
        getdata();
    }, []);
    if (unauthenticated) {
        return <Unauthenticated />;
    }
    const updateuser = async (e) => {
        e.preventDefault();
        const { name, email, work, add, mobile, desc, age } = inpval;
        const res2 = await fetch(`${process.env.REACT_APP_API_URL}/updateuser/${id}`, {
            method: "PATCH",
            // mode: "cors",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `${localStorage.getItem('user')}`
            },
            body: JSON.stringify({
                name, email, mobile, work, age, desc, add
            })
        });
        const data2 = await res2.json();
        if (res2.status === 404 || !data2)
            alert("fill data");
        else {
            Navigate('/')
            toast.success("Data Updated Successfully")
        }
    }


    return (
        <div className="container">
            <NavLink to="/">home</NavLink>
            <form className="mt-4">
                <div className="row">
                    <div class="mb-3 col-lg-6 col-md-6 col-12">
                        <label for="exampleInputEmail1" class="form-label">Name</label>
                        <input type="text" value={inpval.name} onChange={setdata} name="name" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" />
                    </div>
                    <div class="mb-3 col-lg-6 col-md-6 col-12">
                        <label for="exampleInputPassword1" class="form-label">email</label>
                        <input type="email" value={inpval.email} onChange={setdata} name="email" class="form-control" id="exampleInputPassword1" />
                    </div>
                    <div class="mb-3 col-lg-6 col-md-6 col-12">
                        <label for="exampleInputPassword1" class="form-label">age</label>
                        <input type="text" value={inpval.age} onChange={setdata} name="age" class="form-control" id="exampleInputPassword1" />
                    </div>
                    <div class="mb-3 col-lg-6 col-md-6 col-12">
                        <label for="exampleInputPassword1" class="form-label">Mobile</label>
                        <input type="number" value={inpval.mobile} onChange={setdata} name="mobile" class="form-control" id="exampleInputPassword1" />
                    </div>
                    <div class="mb-3 col-lg-6 col-md-6 col-12">
                        <label for="exampleInputPassword1" class="form-label">Work</label>
                        <input type="text" value={inpval.work} onChange={setdata} name="work" class="form-control" id="exampleInputPassword1" />
                    </div>
                    <div class="mb-3 col-lg-6 col-md-6 col-12">
                        <label for="exampleInputPassword1" class="form-label">Address</label>
                        <input type="text" value={inpval.add} onChange={setdata} name="add" class="form-control" id="exampleInputPassword1" />
                    </div>
                    <div class="mb-3 col-lg-12 col-md-12 col-12">
                        <label for="exampleInputPassword1" class="form-label">Description</label>
                        <textarea name="desc" value={inpval.desc} onChange={setdata} className="form-control" id="" cols="30" rows="5"></textarea>
                    </div>

                    <button type="submit" onClick={updateuser} class="btn btn-primary">Submit</button>
                </div>
            </form>
        </div>
    )
}
export default Edit;
