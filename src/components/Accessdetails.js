import React, { useEffect } from "react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
export default function Accessdetails({
  setShowNavbar,
  setHosbar,
  setPatientbar,
}) {
  const navigate = useNavigate();
  useEffect(() => {
    // After redirecting to /Hoshome, change showNavbar to true
    setShowNavbar(true);
    setHosbar(true);
    setPatientbar(false);
    const apiUrl = "http://127.0.0.1:5000/api/redirecth";
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

  let [pname, setpname] = useState("");
  let [aadhar, setaadhar] = useState("");
  let [contact, setcontact] = useState("");
  let [age, setage] = useState("");
  let [gender, setgender] = useState("");
  let [height, setheight] = useState("");
  let [weight, setweight] = useState("");
  let [blood, setblood] = useState("");
  let [error, setError] = useState("");
  const [det, setdet] = useState(false);
  let apiUrl;
  const handleLogin = (e) => {
    e.preventDefault();
    console.log('hello');
    if(aadhar)
    {
    apiUrl = "http://127.0.0.1:5000/api/access/"+aadhar;
  }
    else
    {
      apiUrl = "http://127.0.0.1:5000/api/access/test";
    }
    fetch(apiUrl, {
      method: "GET", // Use the appropriate HTTP method (POST, GET, etc.)
      headers: {
        "Content-Type": "application/json",
      },
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
        setdet(true);
        if(data){
          setpname(data.pname);       // Update state variables with fetched data
        setcontact(data.contact);
        setage(data.age);
        setgender(data.gender);
        setheight(data.height);
        setweight(data.weight);
        setblood(data.bloodgrp);
        setError("");
        }
        else{
          setError("Enter correct number");
          setdet(false);
        }
        
      });
  };
  
  return (
    <div>
      <section class="contact_section layout_padding-bottom">
        <div class="container">
          <div class="heading_container">
            <h2 style={{ margin: "15px" }}>General Details of the Patient</h2><br></br>
            {error && <p style={{ color: "red" }}>{error}</p>}
          </div>
          <div class="form_container">
            <form action="">
              <div>
                <label for="ano">Please Enter Patient's Aadhar number</label>
                <br></br>
                <input
                  type="text"
                  id="ano"
                  placeholder="Patient's Aadhar Number"
                  value = {aadhar}
                  onChange={(e) => setaadhar(e.target.value)}
                />
              </div>
            </form>
            <button style={{ margin: "20px" }} onClick = {handleLogin}>SUBMIT</button>
          </div>
          
          <div class="row">
          { det && (
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
                      readonly
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Emergency Contact(s)"
                      value={contact}
                      onChange={(e) => setcontact(e.target.value)}
                      readonly 
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Age"
                      value={age}
                        onChange={(e) => setage(e.target.value)}
                        readonly
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Gender"
                      value={gender}
                        onChange={(e) => setgender(e.target.value)}
                        readonly
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Height"
                      value={height}
                        onChange={(e) => setheight(e.target.value)}
                        readonly
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Weight"
                      value={weight}
                        onChange={(e) => setweight(e.target.value)}
                        readonly
                    />
                  </div>
                  <div>
                    <input
                      type="text"
                      style={{ margin: "15px" }}
                      placeholder="Blood Group"
                      value={blood}
                        onChange={(e) => setblood(e.target.value)}
                        readonly
                    />
                  </div>

                </form>
              </div>
            </div>)}
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
