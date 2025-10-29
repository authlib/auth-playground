Translations are done with `Weblate <https://hosted.weblate.org/projects/authlib/auth-playground>`__.

The following commands are there as documentation, only the message extraction is needed for contributors.
All the other steps are automatically done with Weblate.


Message extraction
~~~~~~~~~~~~~~~~~~

After you have edited translatable strings, you should extract the messages with:

.. code-block:: console

    $ pybabel extract --mapping-file pyproject.toml --copyright-holder="Yaal Coop" --output-file src/auth_playground/translations/messages.pot src

Language addition
~~~~~~~~~~~~~~~~~

You can add a new language manually with the following command, however this should not be needed as Weblate takes car of this:

.. code-block:: console

    $ pybabel init --input-file src/auth_playground/translations/messages.pot --output-dir src/auth_playground/translations --locale <LANG>

Catalog update
~~~~~~~~~~~~~~

You can update the catalogs with the following command, however this should not be needed as Weblate automatically update language catalogs when it detects new strings or when someone translate some existing strings.
Weblate pushes happen every 24h.

.. code-block:: console

    $ pybabel update --input-file src/auth_playground/translations/messages.pot --output-dir src/auth_playground/translations --ignore-obsolete --no-fuzzy-matching --update-header-comment

Catalog compilation
~~~~~~~~~~~~~~~~~~~

You can compile the catalogs with the following command, however this should not be needed as catalogs are automatically compiled before running the unit tests, before launching the demo and before compiling the auth-playground python package:

.. code-block:: console

    $ pybabel compile --directory src/auth_playground/translations --statistics
