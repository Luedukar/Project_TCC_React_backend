const bcrypt = require("bcrypt");

(async () => {
  const hash = await bcrypt.hash("102030", 10);
  console.log(hash);
})();
