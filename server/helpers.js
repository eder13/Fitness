function convertExpirationTimeFromMinutesToSeconds(timeMinutes = '60m') {
    const regex = /^(\d+|\d+\.\d+)(m|mins|minutes|minute|min)/;
    const match = regex.exec(timeMinutes);
    const value = Number(match[1]);
    return Math.round(value * 60);
}

module.exports = {
    convertExpirationTimeFromMinutesToSeconds
}
