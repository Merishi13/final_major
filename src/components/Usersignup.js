import React, { useState, useEffect } from "react";
import styles from "../login.module.css"; // Import the CSS module
import { Link, Navigate } from "react-router-dom";
import { useNavigate } from "react-router-dom";

export default function Usersignup({
  setShowNavbar,
  setHosbar,
  setPatientbar,
}) {
  useEffect(() => {
    setShowNavbar(false);
    setHosbar(false);
    setPatientbar(false);
  }, []);
  const navigate = useNavigate();
  const [aadhar, setaadhar] = useState("");
  const [password, setpassword] = useState("");
  const [fname, setfname] = useState("");
  const [email, setemail] = useState("");
  const [error, setError] = useState("");

  const handleLogin = (e) => {
    const apiUrl = "http://127.0.0.1:5000/api/register";
    const requestBody = {
      aadhar: aadhar,
      password: password,
      firstname: fname,
      email: email,
    };
    fetch(apiUrl, {
      method: "PUT", // Use the appropriate HTTP method (POST, GET, etc.)
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        console.log("response", response);
        return response.json();
      })
      .then((data) => {
        console.log(data);
        if (data.message) {
          if (data.message === "SUCCESS") {
            alert("Signed up Succesfully")
            navigate("/");
          } else {
            setError("User already exists");
          }
        } else {
          setError("Fill in Correct Details");
        }
      });
    e.preventDefault();
    setShowNavbar(false);
    setHosbar(false);
    setPatientbar(false);
    
  };

  const handleLogin1 = (e) =>
  {
    navigate("/");
  }

  return (
    <div className={`${styles.rishibody}`}>
      <div className={`${styles.container1}`} id="container1">
        <div className={`${styles.formContainer} ${styles.signInContainer1}`}>
          <form className={`${styles.rishiform}`} action="#">
          {error && <p style={{ color: "red" }}>{error}</p>}
            <h1 className={`${styles.rishih1}`}>Sign Up</h1>
            {/* <span className={`${styles.rishispan}`}>or use your account</span> */}
            <input
              className={`${styles.rishiinput}`}
              type="name"
              placeholder="Full Name"
              value={fname}
              onChange={(e) => setfname(e.target.value)}
              required
            />
            <input
              className={`${styles.rishiinput}`}
              type="text"
              placeholder="Aadhar Number"
              value={aadhar}
              onChange={(e) => setaadhar(e.target.value)}
              required
            />
            <input
              className={`${styles.rishiinput}`}
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setemail(e.target.value)}
              required
            />
            <input
              className={`${styles.rishiinput}`}
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setpassword(e.target.value)}
              required
            />
            {/* <a className={`${styles.rishia}`} href="#">
              Forgot your password?
            </a> */}
            <button className={`${styles.rishibutton2}`} onClick={handleLogin}>
              Sign Up
            </button>
          </form>
        </div>
        <div className={`${styles.overlayContainer1}`}>
          <div className={`${styles.overlay2}`}>
            <div className={`${styles.overlayPanel} ${styles.overlayRight}`}>
              <h1 className={`${styles.rishih1}`}>Hello, India!</h1>
              <p className={`${styles.riship}`}>
                Already have an Account and ready to access your records?
              </p>
              <button
                className={`${styles.rishibutton} ${styles.ghost}`}
                onClick={handleLogin1}
                id="signUp"
              >
                Login
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
