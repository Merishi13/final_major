/* eslint-disable no-undef */
import React, { useEffect } from "react";
import { useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { useNavigate } from "react-router-dom"; 

export default function Fillform({ setShowNavbar, setPatientbar, setHosbar }) {
  useEffect(() => {
    // After redirecting to /Hoshome, change showNavbar to true
    setShowNavbar(true);
    setPatientbar(true);
    setHosbar(false);
    const apiUrl = "http://127.0.0.1:5000/api/redirectp";
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
      if (data.redirect) {
        // Redirect to the dashboard page on successful login
        if (data.redirect === "true") {
          
          navigate("/");
        }
      }
    })
  }, []);
  const navigate = useNavigate();
  const [pname, setpname] = useState("");
  const [contact, setcontact] = useState("");
  const [age, setage] = useState("");
  const [gender, setgender] = useState("");
  const [height, setheight] = useState("");
  const [weight, setweight] = useState("");
  const [blood, setblood] = useState("");
  const [error, setError] = useState("");
  const handleLogin = (e) => {
    e.preventDefault();
    const apiUrl = "http://127.0.0.1:5000/api/fillform";
    const requestBody = {
      name: pname,
      contact: contact,
      age: age,
      gender: gender,
      height: height,
      weight:weight,
      bloodgrp:blood
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
            alert("Data Entered succesfully")
            navigate("/Fillform")
          } else {
            setError("Fill all details");
          }
        } else {
          setError("Fill all details");
        }
      });
  };

  return (
    <div>
      <section class="contact_section layout_padding-bottom">
        <div class="container">
          <div class="heading_container">
            <h2 style={{ margin: "0px" }}>Fill in General Details</h2><br></br>
            {error && <p style={{ color: "red" }}>{error}</p>}
          </div>
          <div class="row">
            <div class="col-md-7">  
              <div class="form_container">
                <form action="">
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Patient's Full Name"
                      value={pname}
                      onChange={(e) => setpname(e.target.value)}
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Emergency Contact(s)"
                      value={contact}
                      onChange={(e) => setcontact(e.target.value)}
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Age"
                      value={age}
                      onChange={(e) => setage(e.target.value)}
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Gender"
                      value={gender}
                      onChange={(e) => setgender(e.target.value)}
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Height"
                      value={height}
                      onChange={(e) => setheight(e.target.value)}
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Weight"
                      value={weight}
                      onChange={(e) => setweight(e.target.value)}
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Blood Group"
                      value={blood}
                      onChange={(e) => setblood(e.target.value)}
                    />
                  </div>  

                  <div class="btn_box">
                    <button style={{ margin: "15px" }} onClick={handleLogin}>SUBMIT</button>
                  </div>
                </form>
              </div>
            </div>
            <div class="col-md-5">
              <div class="img-box">
                <img
                  src="/contact-img.jpg"
                  alt=""
                  style={{ width: "75%" }}
                ></img>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
