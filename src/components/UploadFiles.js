import React, { useEffect } from "react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
export default function UploadFiles({
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

  const [aadhar, setaadhar] = useState("");
  const [file, setFile] = useState(null);
  const [det, setdet] = useState(false);
  let [error, setError] = useState("");

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);
  };

  const checkUser = () =>{
    fetch("http://127.0.0.1:5000/api/checkuser/"+aadhar, {
      // method: "PUT",
      // body: formData,
    })
    .then((response) => response.json())
      .then((data) => {
        if(data)
        {
          setError(null);
            setdet(true);
        }
        else{
          setError("Enter correct number");
          setdet(false);
        }
      })
      .catch((error) => {
        console.error("Error uploading file:", error);
      });
  }

  const handleUpload = () => {
    const formData = new FormData();
    formData.append("file", file);

    fetch("http://127.0.0.1:5000/api/upload/"+aadhar, {
      method: "PUT",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("File uploaded successfully:", data);
        alert("file uploaded succesfully");
      })
      .catch((error) => {
        console.error("Error uploading file:", error);
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
            <h2 style={{ margin: "18px" }}>
              Upload all of Patient's Medical Records here!
            </h2>

            <div class="form_container">
              <form action="">
                <div>
                  <label for="ano">Please Enter Patient's Aadhar number</label>
                  <br></br>
                  {error && <p style={{ color: "red" }}>{error}</p>}
                  <input
                    type="text"
                    id="ano"
                    placeholder="Patient's Aadhar Number"
                    value = {aadhar}
                      onChange={(e) => setaadhar(e.target.value)}
                  />
                </div>
              </form>
              <button style={{ margin: "15px" }} onClick = {checkUser}>SUBMIT</button>
            </div>

            { det && (<table id="customers" style={{ width: "100%", margin: "18px" }}>
              <tr style={evenRowStyle}>
                <th style={hoverRowStyle}>Select File to upload</th>
                <th style={hoverRowStyle}>Upload File</th>
              </tr>
              <tr style={evenRowStyle}>
                <td style={hoverRowStyle}>
                  <div class="btn_box">
                  <input type = "file" onChange={handleFileChange} style={{ backgroundColor: "#20c997" }} />
                  </div>{" "}
                </td>
                <td style={hoverRowStyle}>
                  <div class="btn_box">
                  <button onClick={handleUpload} style={{ backgroundColor: "#20c997" }}>
                        UPLOAD FILE
                      </button>
                  </div>
                </td>
              </tr>
            </table>)}
          </div>
        </div>
      </section><br></br><br></br><br></br>
      {!det && (<div><br></br><br></br><br></br><br></br></div>)}
    </div>
  );
}
