/* eslint-disable no-undef */
import React from "react";
import { Link, Navigate } from "react-router-dom";
import { useNavigate } from "react-router-dom";

import PropTypes from "prop-types";

export default function Navbar(props) {
  const { hospitalBar } = props;
  const navigate = useNavigate();
  const handlelogout = () => {
    fetch("http://127.0.0.1:5000/api/logout", {
      method: "PUT"
    })
    .then((response) => response.json())
      .then((data) => {

        navigate("/");

      })
      .catch((error) => {
        console.error("Error uploading file:", error);
      });
  };
  return (
    <div>
      <nav
        className="navbar navbar-expand-lg bg-body-tertiary"
        style={{ background: "#00c6a9" }}
      >
        <div className="container-fluid" style={{ background: "#00c6a9" }}>
          <a className="navbar-brand" href="/">
            <img
              src="/Jeevanlogo.png"
              alt="Bootstrap"
              width="100"
              height="100"
            />
          </a>
          <button
            className="navbar-toggler"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#navbarSupportedContent"
            aria-controls="navbarSupportedContent"
            aria-expanded="false"
            aria-label="Toggle navigation"
          >
            <span className="navbar-toggler-icon"></span>
          </button>
          <div className="collapse navbar-collapse" id="navbarSupportedContent">
            <ul className="navbar-nav me-auto mb-2 mb-lg-0">
              <li className="nav-item">
                <a className="nav-link active" aria-current="page">
                  {props.abouttext}
                </a>
              </li>
              <li className="nav-item">
                <a className="nav-link">
                  Contact Us
                </a>
              </li>
              <li className="nav-item dropdown">
                <a
                  className="nav-link dropdown-toggle"
                  href="/"
                  role="button"
                  data-bs-toggle="dropdown"
                  aria-expanded="false"
                >
                  More
                </a>
                <ul className="dropdown-menu" style={{ background: "#00c6a9" }}>
                  <li>
                    <a className="dropdown-item">
                      <Link style = {{"text-decoration": "none", color: "black", cursor: "pointer"}} to={hospitalBar ? "/HospitalHome" : "/PatientHome"}>
                        {props.action1}
                      </Link>
                    </a>
                  </li>
                  <li>
                    <a className="dropdown-item">
                      <Link style = {{"text-decoration": "none", color: "black", cursor: "pointer"}} to={hospitalBar ? "/AccessForm" : "/Fillform"}>
                        {props.action2}
                      </Link>
                    </a>
                  </li>
                  {/* <li>
                    <hr className="dropdown-divider" />
                  </li> */}
                  <li>
                    <a className="dropdown-item">
                      <Link style = {{"text-decoration": "none", color: "black", cursor: "pointer"}} to={hospitalBar ? "/AccRecords" : "/Accessrecords"}>
                        {props.action3}
                      </Link>
                    </a>
                  </li>
                  <li>
                    <a className="dropdown-item" href={props.ral4}>
                      <Link style = {{"text-decoration": "none", color: "black", cursor: "pointer"}} to="/UpdateFiles">{props.action4}</Link>
                    </a>
                  </li>
                </ul>
              </li>
            </ul>
            <button
              className="btn"
              // href={props.ral5}
              style={{
                backgroundColor: " isHover ? 'lightblue' : 'rgb(0, 191, 255)'",
                border: "2px solid black",
                boxShadow:
                  "0 8px 16px 0 rgba(0,0,0,0.2), 0 6px 20px 0 rgba(0,0,0,0.19)",
              }}
              onClick={handlelogout}
            >
              Logout

            </button>
          </div>
        </div>
      </nav>
    </div>
  );
}

Navbar.propTypes = {
  abouttext: PropTypes.string,
  action1: PropTypes.string,
  action2: PropTypes.string,
  action3: PropTypes.string,
};
