from distutils.command.build import build
from setuptools import setup
from setuptools.command.install import install as _install


class install(_install):
    def run(self):
        self.run_command('build')
        _install.run(self)

setup(name="awsthreatprep",
      version="0.1.1",
      author="Alex McCormack",
      author_email="developer@amccormack.net",
      packages=["awsthreatprep"],
      license="MIT",
      description="TODO",
      use_2to3=True,
      install_requires=['boto3'])
