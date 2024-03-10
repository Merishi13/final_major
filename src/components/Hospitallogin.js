import React, { useEffect } from "react";
import styles from "../login.module.css"; // Import the CSS module
import { Link, Navigate } from "react-router-dom";
import { useNavigate } from "react-router-dom";
import { useState } from "react";

export default function HospitalLogin({
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
  const [hospitalNumber, setHospitalNumber] = useState(""); // State to store the hospital number
  const [password, setPassword] = useState(""); // State to store the password
  const [error, setError] = useState("");

  const handleLogin = (e) => {
    e.preventDefault();
    const apiUrl = "http://127.0.0.1:5000/api/data/" + hospitalNumber; // Replace with your API endpoint

    fetch(apiUrl, {
      method: "GET", // Use the appropriate HTTP method (POST, GET, etc.)
      headers: {
        "Content-Type": "application/json",
      },
      // body: JSON.stringify(requestBody),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        // Handle the API response data as needed
        // For example, you can check if the login was successful
        console.log(data);
        console.log(password);
        if (data.password) {
          // Redirect to the dashboard page on successful login
          if (data.password === password) {
            console.log(data.password);
            console.log(password);
            fetch("http://127.0.0.1:5000/api/change/" + hospitalNumber, {
              method: "PUT", // Use the appropriate HTTP method (POST, GET, etc.)
              headers: {
                "Content-Type": "application/json",
              },
              // body: JSON.stringify(requestBody),
            })
            setShowNavbar(true);
            setHosbar(true);
            setPatientbar(false);
            navigate("/HospitalHome");
          } else {
            // Handle unsuccessful login (e.g., display an error message)
            console.log(data.password);
            console.log(password);
            setError("Wrong password");
          }
        } else {
          setError("Fill in Correct Details");
        }
      })
      .catch((error) => {
        // Handle any network errors or exceptions here
        console.error("API call error:", error);
        // alert("API call error:", error);
      });

    
    
  };
  const handleLogin1 = () => {
    setShowNavbar(false);
    setHosbar(false);
    setPatientbar(false);
    navigate("/");
  };
  return (
    <div className={`${styles.rishibody}`}>
      <div className={`${styles.container1}`} id="container1">
        <div className={`${styles.formContainer} ${styles.signInContainer1}`}>
          <form className={`${styles.rishiform}`} action="#">
          {error && <p style={{ color: "red" }}>{error}</p>}  <br></br><br></br>
            <h1 className={`${styles.rishih1}`}>Login</h1>
            {/* <span className={`${styles.rishispan}`}>or use your account</span> */}
            <input
              className={`${styles.rishiinput}`}
              type="text"
              placeholder="Hospital ID"
              value={hospitalNumber}
              onChange={(e) => setHospitalNumber(e.target.value)}
              required
            />
            <input
              className={`${styles.rishiinput}`}
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {/* <a className={`${styles.rishia}`} href="#">
              Forgot your password?
            </a> */}
            <button className={`${styles.rishibutton1}`} onClick={handleLogin}>
              Login
            </button>
          </form>
        </div>
        <div className={`${styles.overlayContainer1}`}>
          <div className={`${styles.overlay1}`}>
            <div className={`${styles.overlayPanel} ${styles.overlayRight}`}>
              <h1 className={`${styles.rishih1}`}>Hello, India!</h1>
              <p className={`${styles.riship}`}>Are you a patient?</p>
              <button
                className={`${styles.rishibutton} ${styles.ghost}`}
                id="signUp"
                onClick={handleLogin1}
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
