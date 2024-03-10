import React, { useEffect } from "react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
export default function AccessPrecords({
  setShowNavbar,
  setHosbar,
  setPatientbar,
}) {
  const navigate = useNavigate();
  const [summary, setSummary] = useState(null);
  let [error, setError] = useState("");
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
  const [aadhar, setaadhar] = useState("");
  const [fileData, setFileData] = useState(null);

  const handledownload = () => {
    fetch("http://127.0.0.1:5000/api/download/"+aadhar, {
      method: "Get",
    })
    .then((response) => response.json())
    .then((data) => {
      // Assuming the data returned from Flask contains file_data as base64
      alert("downloaded succesfully")
    })
    .catch((error) => {
      console.error("Error fetching file data:", error);
    });
  };
  
  const handleUpload = () => {
    let det;
    fetch("http://127.0.0.1:5000/api/retrieve/"+aadhar, {
      method: "Get",
    })
    .then((response) => response.json())
    .then((data) => {
      // Assuming the data returned from Flask contains file_data as base64
      if(data){
        setFileData(data.file_data);
        setError("");
        det = true;
    }
      else{
        setError("Enter correct number");
        setSummary(null);
        det = false;
      }

      if (det == true)
    {
      const apiUrl1 = "http://127.0.0.1:5000/api/summary/"+aadhar;
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
  }
    })
    .catch((error) => {
      setError("Enter correct number");
    });
    console.log(det);
    
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
          <div class="heading_container">
            <h2 style={{ margin: "15px" }}>Access all of Patient's Medical Records here!</h2>
          </div>
          {error && <p style={{ color: "red" }}>{error}</p>}
          <div class="form_container">
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
              <div>
                <button style={{ margin: "20px" }} onClick={handleUpload}>SUBMIT</button>
              </div>

              <table id="customers" style={{ width: "100%", margin: "18px" }}>
                <tr style={evenRowStyle}>
                <th style={hoverRowStyle}>Records</th>
                  <th style={hoverRowStyle}>Summary</th>
                </tr>
                <tr style={evenRowStyle}>
                <td style={hoverRowStyle}>{fileData && <img src={`OIG.jpg;base64,${fileData}`}  />} <button onClick={handledownload}>download</button></td>
                  <td style={hoverRowStyle}>{summary || "Loading summary..."}</td>
                </tr>
              </table>
              <div class="col-md-5">
                <div class="img-box">
                  <img
                    src="/about-img.jpg"
                    alt=""
                    style={{ width: "75%" }}
                  ></img>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section class="info_section">
        <div class="container">
          <div class="info_top">
            <div class="info_logo"></div>
          </div>
        </div>
      </section>
    </div>
  );
}
