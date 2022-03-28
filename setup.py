import setuptools
setuptools.setup(
    name="SickRFH630",
    version="0.4", 
    author="Hadrien Huvelle", 
    description="Lib to use Sick RFH 6320 from python", 
    packages=["SickRFH630"],
    install_requires=["coloredlogs", "six", "ndef"]
)