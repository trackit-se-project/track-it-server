const { verify } = require("jsonwebtoken");

module.exports = {
  checkToken: (req, res, next) => {
    let token = req.get("authorization");

    if (token) {
      token = token.slice(7);

      verify(token, process.env.APP_SECRET, (err, _decoded) => {
        if (err) {
          res.status(401).json({ message: "Unauthorized" });
        } else {
          next();
        }
      });
    } else {
      res.status(401).json({ message: "Unauthorized" });
    }
  },
};
