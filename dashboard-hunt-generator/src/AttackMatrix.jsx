import { useState } from "react";
import attackData from "../attack-matrix.json";
import "./AttackMatrix.css";

const tacticOrder = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Stealth",
  "Defense Impairment",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

function AttackMatrix() {
  const [expanded, setExpanded] = useState({});

  const toggleTechnique = (techId) => {
    setExpanded((prev) => ({
      ...prev,
      [techId]: !prev[techId],
    }));
  };

  return (
    <div className="attack-matrix-container">
    <div className="attack-matrix">
        {tacticOrder.map((tactic) => {

  const techniques = Object.values(attackData[tactic] || {});

  return (



          <div className="tactic-column" key={tactic}>
            <div className="tactic-header">
              {tactic}
            </div>

            {techniques.map((tech) => (
              <div className="technique" key={tech.tech_id}>

                <div
                  className="tech-header"
                  onClick={() => toggleTechnique(tech.tech_id)}
                >
                  <span className="arrow">
                    {expanded[tech.tech_id] ? "▼" : "▶"}
                  </span>

                  <div>
                    <div className="tech-id">
                      {tech.tech_id}
                    </div>

                    <div className="tech-name">
                      {tech.tech_name}{tech.subtechniques.length>0 && ( ` (${tech.subtechniques.length})`)}
                    </div> 

                  </div>
                </div>

                {expanded[tech.tech_id] &&
                  tech.subtechniques &&
                  tech.subtechniques.length > 0 && (

                    <div className="subtechniques">

                      {tech.subtechniques
                        .sort((a, b) =>
                          a.tech_id.localeCompare(
                            b.tech_id,
                            undefined,
                            { numeric: true }
                          )
                        )
                        .map((sub) => (

                          <div
                            className="sub-technique"
                            key={sub.tech_id}
                          >
                            <div className="sub-id">
                              {sub.tech_id}
                            </div>

                            <div className="sub-name">
                              {sub.tech_name.split(":")[1]}
                            </div>
                          </div>

                        ))}

                    </div>

                )}

              </div>
            ))}
          </div>
        );
      })}
    </div>
    <div className="threat-actors-panel">
      <h2> Threat Actor(s) / Malware</h2>
    </div>
    </div>
  );
}

export default AttackMatrix;