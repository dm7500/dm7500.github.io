---
layout: collection
title: "OSCP Prep"
permalink: "/oscp-prep/"
---

{% for page in site.oscp-prep %}

<p><a href="{{ page.url }}">
  {{page.title}}
  <H5>{{page.headline}}</H5>
  <img src="{{page.picture}}" align=center><br>
  <hr></p>


{% endfor %} 

<!-- <ul>
  {% for page in site.oscp-prep %}
    <li>
      <a href="{{ page.url }}">{{ page.title }}</a>
      - {{ page.headline }}
    </li>
  {% endfor %}
</ul> -->