# DefectDojo

[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-orange.svg)](https://www.owasp.org/index.php/OWASP_DefectDojo_Project) [![GitHub release](https://img.shields.io/github/release/DefectDojo/django-DefectDojo.svg)](https://github.com/DefectDojo/django-DefectDojo) [![YouTube Subscribe](https://img.shields.io/badge/youtube-subscribe-%23c4302b.svg)](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ) ![Twitter Follow](https://img.shields.io/twitter/follow/defectdojo.svg?style=social&label=Follow)

[![Unit Tests](https://github.com/DefectDojo/django-DefectDojo/actions/workflows/unit-tests.yml/badge.svg?branch=master)](https://github.com/DefectDojo/django-DefectDojo/actions)[![Integration Tests](https://github.com/DefectDojo/django-DefectDojo/actions/workflows/integration-tests.yml/badge.svg?branch=master)](https://github.com/DefectDojo/django-DefectDojo/actions) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2098/badge)](https://bestpractices.coreinfrastructure.org/projects/2098)

![Screenshot of DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/screenshot1.png)

[DefectDojo](https://www.defectdojo.org/) is a security orchestration and
vulnerability management platform.
DefectDojo allows you to manage your application security program, maintain
product and application information, triage vulnerabilities and
push findings to systems like JIRA and Slack. DefectDojo enriches and
refines vulnerability data using a number of heuristic algorithms that
improve with the more you use the platform.

## Demo

Try out the demo sever at [demo.defectdojo.org](https://demo.defectdojo.org)

Log in with `admin / 1Defectdojo@demo#appsec`. Please note that the demo is publicly accessable and regularly reset. Do not put sensitive data in the demo.

## Quick Start

```sh
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
# building
docker-compose build
# running
docker-compose up
# obtain admin credentials. the initializer can take up to 3 minutes to run
# use docker-compose logs -f initializer to track progress
docker-compose logs initializer | grep "Admin password:"
```

Navigate to <http://localhost:8080>.


## Documentation

- [Official docs](https://defectdojo.github.io/django-DefectDojo/) ([latest](https://defectdojo.github.io/django-DefectDojo/) | [dev](https://defectdojo.github.io/django-DefectDojo/dev))
- [REST APIs](https://defectdojo.github.io/django-DefectDojo/integrations/api-v2-docs/)
- [Client APIs and Wrappers](https://defectdojo.github.io/django-DefectDojo/integrations/api-v2-docs/#clients--api-wrappers)
- [Authentication options](readme-docs/AVAILABLE-PLUGINS.md)

## Supported Installation Options

* [Docker / Docker Compose](readme-docs/DOCKER.md)
* [godojo](https://github.com/DefectDojo/godojo)


## Community, Getting Involved, and Updates

[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/slack-logo-icon.png" alt="Slack" height="50"/>](https://owasp-slack.herokuapp.com/)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/Linkedin-logo-icon-png.png" alt="LinkedIn" height="50"/>](https://www.linkedin.com/company/defectdojo)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/Twitter_Logo.png" alt="Twitter" height="50"/>](https://twitter.com/defectdojo)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/YouTube-Emblem.png" alt="Youtube" height="50"/>](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ)

[Join the slack community](https://owasp-slack.herokuapp.com/) and discussion! Realtime discussion is done in the OWASP Slack Channel, #defectdojo.
Follow DefectDojo on [Twitter](https://twitter.com/defectdojo), [Linkedin](https://www.linkedin.com/company/defectdojo), and [YouTube](https://www.youtube.com/channel/UCWw9qzqptiIvTqSqhOFuCuQ) for project updates!

## Contributing
See our [Contributing guidelines](readme-docs/CONTRIBUTING.md)

## Commercial Support and Training
Commercial support and training is availaible through [10Security](https://10security.com).

10Security was founded by the creators of DefectDojo.
For information please email info@10security.com or visit our [site](https://10security.com).

## About Us

DefectDojo is maintained by:
* Greg Anderson ([@devGregA](https://github.com/devgrega) | [linkedin](https://www.linkedin.com/in/g-anderson/))
* Aaron Weaver ([@aaronweaver](https://github.com/aaronweaver)| [linkedin](https://www.linkedin.com/in/aweaver/) | [@weavera](https://twitter.com/weavera))
* Matt Tesauro ([@mtesauro](https://github.com/mtesauro) | [linkedin](https://www.linkedin.com/in/matttesauro/) | [@matt_tesauro](https://twitter.com/matt_tesauro))

Core Moderators can help you with pull requests or feedback on dev ideas:
* Valentijn Scholten ([@valentijnscholten](https://github.com/valentijnscholten) | [sponsor](https://github.com/sponsors/valentijnscholten) | [linkedin](https://www.linkedin.com/in/valentijn-scholten/))
* Fred Blaise ([@madchap](https://github.com/madchap) | [linkedin](https://www.linkedin.com/in/fredblaise/))
* Cody Maffucci ([@Maffooch](https://github.com/maffooch) | [linkedin](https://www.linkedin.com/in/cody-maffucci))

Moderators can help you with pull requests or feedback on dev ideas:
* Damien Carol ([@damnielcarol](https://github.com/damiencarol) | [linkedin](https://www.linkedin.com/in/damien-carol/))
* Stefan Fleckenstein ([@StefanFl](https://github.com/stefanfl) | ([linkedin](https://www.linkedin.com/in/stefan-fleckenstein-6a456a30/))
* Jannik Jürgens ([@alles-klar](https://github.com/alles-klar))
* Pascal Trovatelli ([@ptrovatelli](https://github.com/ptrovatelli) | [Sopra Steria](https://www.soprasteria.com/))
* Alex Dracea ([linkedin](https://www.linkedin.com/in/alexandru-marin-dracea-910b51122/))


## Hall of Fame

* Charles Neill ([@ccneill](https://twitter.com/ccneill)) – Charles served as a
    DefectDojo Maintainer for years and wrote some of Dojo's core functionality.
* Jay Paz ([@jjpaz](https://twitter.com/jjpaz)) – Jay was a DefectDojo
  maintainer for years. He performed Dojo's first UI overhaul, optimized code structure/features, and added numerous enhancements.


## Sponsors
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/10Security-logo.png" github-user="devgrega" alt="10Security" height="65"/>](https://10security.com)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/isaac.png" github-user="valentijnscholten" alt="ISAAC" height="80"/>](https://isaac.nl)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/timo-pagel-logo.png" github-user="wurstbot" alt="Tim Pagel" height="65" />](https://pagel.pro/)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/cloudbees-logo.png" github-user="madchap" alt="Cloudbees" height="65" />](https://cloudbees.com/)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/arrival.png" github-user="ansidorov" alt="ARRIVAL" height="65" />](https://arrival.com)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/WHP.png" github-user="mtesauro" alt="WeHackPurle" height="120" />](https://wehackpurple.com/)
[<img src="https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/dev/docs/static/images/maibornwolff-logo.png" github-user="StefanFl" alt="MiabornWolff" height="120" />]((https://www.maibornwolff.de/en))

## Security

Please report Security issues via our [disclosure policy](readme-docs/SECURITY.md).

## License

DefectDojo is licensed under the [BSD Simplified license](LICENSE.md)
