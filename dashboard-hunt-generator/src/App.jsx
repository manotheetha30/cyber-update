import { useState } from "react";
import "./App.css";
import AttackMatrix from "./AttackMatrix";

function Header() {
  return (
    <header className="header">
      <h1>HUNT HYPOTHESIS GENERATION DASHBOARD</h1>
    </header>
  );
}

function UrlCard() {
  const [url, setUrl] = useState("");

  const handleSubmit = () => {
    console.log("URL:", url);

    // TODO: Call your backend here
    // fetch(...)
  };

  return (
    <div className="card">
      <h2>Analyze a single article</h2>

      <p>Enter the URL of an article to analyze.</p>

      <input
        type="text"
        placeholder=""
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      <button onClick={handleSubmit}>
       Analyze
      </button>
    </div>
  );
}

function BatchCard() {
  const handleClick = () => {
    console.log("Analyze Recent Threat Articles");

    // TODO: Call your backend here
    // fetch(...)
  };
  const [selectedSources, setSelectedSources] = useState([    "The Hacker News",
    "BleepingComputer",
    "Krebs on Security",
    "Dark Reading",
    "The Record",
    "CyberScoop",
    "SecurityWeek"]);

  const sources = [
    "The Hacker News",
    "BleepingComputer",
    "Krebs on Security",
    "Dark Reading",
    "The Record",
    "CyberScoop",
    "SecurityWeek",
  ];
  const [days, setDays] = useState("1");
  const toggleSource = (source) => {
    if (selectedSources.includes(source)) {
      setSelectedSources(
        selectedSources.filter((s) => s !== source)
      );
    } else {
      setSelectedSources([...selectedSources, source]);
    }
  };

  return (
    <div className="card">
      <h2>Analyze Recent Threat Articles</h2>

      <p>
        Run the intelligence pipeline on cybersecurity articles from the selected lookback period and generate hunt hypotheses for actionable incidents.
      </p>
    
      <label htmlFor="lookback">Lookback Period</label>

      <select
        id="lookback"
        value={days}
        onChange={(e) => setDays(e.target.value)}
      >
        <option value="1">Last 1 Day</option>
        <option value="3">Last 3 Days</option>
        <option value="7">Last 7 Days</option>
      </select>
      <h3>News Sources</h3>

      <div className="sources">
        {sources.map((source) => (
          <label key={source} className="source-item">
            <input
              type="checkbox"
              checked={selectedSources.includes(source)}
              onChange={() => toggleSource(source)}
            />
            {source}
          </label>
        ))}
      </div>

      <button onClick={handleClick}>
        Start Analysis
      </button>
    </div>
  );
}

function App() {
  return (
    <div className="app">
      <Header />

      <main className="dashboard">
        <UrlCard />
        <BatchCard />
        <AttackMatrix/>
      </main>
    </div>
  );
}

export default App;