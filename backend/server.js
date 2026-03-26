const path = require("path");
const express = require("express");
const cors = require("cors");
require("dotenv").config();

const analyzeRoute = require("./routes/analyze");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.use("/api/analyze", analyzeRoute);

const frontendDir = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendDir));
app.get("/", (req, res) => res.sendFile(path.join(frontendDir, "index.html")));

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

