/* eslint-disable no-undef */
import React, { useEffect } from "react";
import { useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { useNavigate } from "react-router-dom";

export default function AccessRecords({
  setShowNavbar,
  setPatientbar,
  setHosbar,
}) {
  //   const inputRef = useRef < HTMLInputElement > null;

  //   useEffect(() => {
  //     // 👉️ ref could be null here
  //     if (inputRef.current != null) {
  //       // 👉️ TypeScript knows that ref is not null here
  //       inputRef.current.focus();
  //     }
  //   }, []);
  const navigate = useNavigate();
  const [summary, setSummary] = useState(null);
  useEffect(() => {
    // After redirecting to /Hoshome, change showNavbar to true
    setShowNavbar(true);
    setPatientbar(true);
    setHosbar(false);

    const apiUrl1 = "http://127.0.0.1:5000/api/summary";
    fetch(apiUrl1, {
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
      if (data.summary) {
        // Redirect to the dashboard page on successful login
        setSummary(data.summary);
      }
    })


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
  const [fileData, setFileData] = useState(null);
  const handledownload = () => {
    fetch("http://127.0.0.1:5000/api/downloadp", {
      method: "Get",
    })
    
    .then((response) => response.json())
    .then(() => {
      alert("file downloaded succesfully")
      console.log("hello");
      // Assuming the data returned from Flask contains file_data as base64
      
    })
    .catch((error) => {
      console.error("Error fetching file data:", error);
    });
  };

  const evenRowStyle = {
    backgroundColor: "#f2f2f2",
    border: "1px solid #ddd",
    padding: "8px",
    paddingTop: "12px",
    paddingBottom: "12px",
    textAlign: "left",
    backgroundColor: "#20c997",
  };

  const hoverRowStyle = {
    backgroundColor: "#ddd",
    border: "1px solid #ddd",
    padding: "8px",
    paddingTop: "12px",
    paddingBottom: "12px",
    textAlign: "left",
    backgroundColor: "#20c997",
  };
  return (
    <div>
      <section class="contact_section layout_padding-bottom">
        <div class="container">
          <div
            class="heading_container"
            style={{ bordercollapse: "collapse", width: "100%" }}
          >
            <h2 style={{ margin: "0px" }}>
              Access all of Your Medical Records here!
            </h2>

            <table id="customers" style={{ width: "100%", margin: "18px" }}>
              <tr style={evenRowStyle}>
                <th style={hoverRowStyle}>Records</th>
                <th style={hoverRowStyle}>Summary</th>
              </tr>
              <tr style={evenRowStyle}>
              <td style={hoverRowStyle}>{fileData && <img src={`/public/OIG.jpg;base64,${fileData}`} alt="Records" />}<button onClick={handledownload}>download</button> </td>
                <td style={hoverRowStyle}> {summary || "Loading summary..."}</td>
              </tr>
            </table>
            <div class="col-md-5">
              <div class="img-box">
                <img
                  src="/treatment-side-img.jpg"
                  alt=""
                  style={{ width: "65%" }}
                ></img>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
