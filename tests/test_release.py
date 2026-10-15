import io
import os
import tempfile
import unittest
from unittest.mock import patch

import app as portal


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=portal.BASE_DIR)
        self.addCleanup(self.temp.cleanup)
        self.old_db = portal.DB_PATH
        self.old_upload = portal.app.config['UPLOAD_FOLDER']
        portal.DB_PATH = os.path.join(self.temp.name, 'test.db')
        portal.app.config['UPLOAD_FOLDER'] = os.path.join(self.temp.name, 'uploads')
        os.mkdir(portal.app.config['UPLOAD_FOLDER'])
        self.addCleanup(self.restore)
        portal.init_db()
        self.client = portal.app.test_client()

    def restore(self):
        portal.DB_PATH = self.old_db
        portal.app.config['UPLOAD_FOLDER'] = self.old_upload

    def csrf(self):
        with self.client.session_transaction() as sess:
            sess['_csrf'] = 'test-token'
        return 'test-token'

    def insert_row(self):
        conn = portal.get_db_connection()
        data = {field: '' for field in portal.FULL_FORM_FIELDS}
        data.update(student_number='FR-2026-12345', school_year='2026-2027',
                    applicant_type='New Freshman', year_level='1st Year',
                    course='BS Computer Science', first_name='Test', last_name='Applicant',
                    gender='Female', civil_status='Single', email='test@example.org',
                    address='Test', zip_code='1000', guardian_name='Parent',
                    guardian_relationship='Mother', guardian_contact='123',
                    last_school_attended='School', year_graduated='2026')
        portal.insert_application(conn, data, {}, 'online')
        conn.commit()
        conn.close()

    def test_pages_render_and_staff_is_protected(self):
        for path in ('/', '/apply', '/status'):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertEqual(self.client.get('/staff/login').status_code, 404)
        self.assertEqual(self.client.get('/admin').status_code, 404)
        self.assertEqual(self.client.get('/encode').status_code, 404)
        self.assertEqual(self.client.get('/uploads/private.pdf').status_code, 404)

    def test_demo_url_entry_and_csrf(self):
        with patch.object(portal, 'DEMO_MODE', True), patch.dict(portal.app.jinja_env.globals, demo_mode=True):
            self.assertEqual(self.client.get('/admin').status_code, 404)
            response = self.client.get('/login.php', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Application ledger', response.data)
            self.assertEqual(self.client.get('/encode').status_code, 200)
            self.assertEqual(self.client.get('/staff/logout').status_code, 405)
            self.assertEqual(self.client.post('/staff/logout', data={}).status_code, 403)
            self.csrf()
            self.assertEqual(self.client.post('/staff/logout', data={'_csrf': 'test-token'}).status_code, 302)
            self.assertEqual(self.client.get('/admin').status_code, 404)
            self.assertEqual(self.client.get('/login.html').status_code, 302)

    def test_pass_requires_lookup_or_signed_link(self):
        self.insert_row()
        path = '/tap/FR-2026-12345'
        self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(self.client.get(path + '/qr.png').status_code, 404)
        self.csrf()
        result = self.client.post('/status', data={
            '_csrf': 'test-token', 'ref': 'FR-2026-12345',
            'last_name': 'Applicant'}, follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        self.assertIn(b'Test Applicant', result.data)
        self.assertNotIn(b'PSA Registry', result.data)
        token = portal._pass_token('FR-2026-12345')
        fresh = portal.app.test_client()
        self.assertEqual(fresh.get(path + '?token=' + token).status_code, 200)
        self.assertEqual(fresh.get(path + '?token=bad').status_code, 404)

    def test_upload_content_validation(self):
        from werkzeug.datastructures import FileStorage
        fake = FileStorage(stream=io.BytesIO(b'not an image'), filename='photo.png')
        self.assertIsNotNone(portal.validate_document(fake))
        fake_pdf = FileStorage(stream=io.BytesIO(b'not a pdf'), filename='record.pdf')
        self.assertIsNotNone(portal.validate_document(fake_pdf))

    def test_online_submission_and_api_csrf(self):
        from PIL import Image
        self.csrf()
        self.assertEqual(self.client.post('/api/ai-lens-scan-psa').status_code, 403)
        data = {field: 'Test' for field in (
            'school_year', 'applicant_type', 'year_level', 'course', 'first_name',
            'last_name', 'gender', 'civil_status', 'contact_number', 'address',
            'zip_code', 'guardian_name', 'guardian_relationship', 'guardian_contact',
            'last_school_attended', 'year_graduated', 'psa_birth_date',
            'psa_birth_place', 'psa_registry_number', 'psa_mother_name',
            'psa_father_name', 'tor_lrn', 'tor_shs_track_strand', 'tor_general_average')}
        data.update(_csrf='test-token', privacy_ack='yes', email='test@example.org')
        picture = io.BytesIO()
        Image.new('RGB', (2, 2), 'blue').save(picture, format='PNG')
        image_bytes = picture.getvalue()
        data.update(pic_2x2=(io.BytesIO(image_bytes), 'photo.png'),
                    pic_1x1=(io.BytesIO(image_bytes), 'photo.png'),
                    psa_birth_cert=(io.BytesIO(b'%PDF-1.4\n%%EOF'), 'psa.pdf'),
                    transcript=(io.BytesIO(b'%PDF-1.4\n%%EOF'), 'school.pdf'))
        response = self.client.post('/submit', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/tap/', response.location)
        conn = portal.get_db_connection()
        self.assertEqual(conn.execute('SELECT COUNT(*) FROM applications').fetchone()[0], 1)
        conn.close()

    def test_gemini_sdk_request_shape_without_network(self):
        with patch.object(portal, 'gemini_client', create=True) as client:
            client.models.generate_content.return_value.text = '{"first_name":"A"}'
            text, model = portal._gemini_generate('Extract')
            self.assertEqual(text, '{"first_name":"A"}')
            client.models.generate_content.assert_called_once_with(model=model, contents='Extract')

    def test_vercel_demo_without_uploads(self):
        with patch.object(portal, 'DEMO_MODE', True), patch.dict(portal.app.jinja_env.globals, demo_mode=True):
            self.csrf()
            page = self.client.get('/apply')
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'School project demo', page.data)
            self.assertIn(b'demo_ack', page.data)
            self.assertEqual(self.client.post('/api/ai-lens-scan-psa',
                            headers={'X-CSRF-Token': 'test-token'}).status_code, 503)
            fields = {field: 'Test' for field in (
                'school_year', 'applicant_type', 'year_level', 'course', 'first_name',
                'last_name', 'gender', 'civil_status', 'contact_number', 'address',
                'zip_code', 'guardian_name', 'guardian_relationship', 'guardian_contact',
                'last_school_attended', 'year_graduated', 'psa_birth_date',
                'psa_birth_place', 'psa_registry_number', 'psa_mother_name',
                'psa_father_name', 'tor_lrn', 'tor_shs_track_strand', 'tor_general_average')}
            fields.update(_csrf='test-token', privacy_ack='yes', demo_ack='yes',
                          email='test@example.org')
            result = self.client.post('/submit', data=fields)
            self.assertEqual(result.status_code, 302)
            ref = result.location.rsplit('/', 1)[-1]
            with self.client.session_transaction() as sess:
                demo = sess['demo_pass']
            token = portal._pass_token(ref, demo)
            conn = portal.get_db_connection()
            conn.execute('DELETE FROM applications')
            conn.commit()
            conn.close()
            fresh = portal.app.test_client()
            self.assertEqual(fresh.get('/tap/' + ref + '?token=' + token).status_code, 200)
            self.assertEqual(fresh.get('/tap/' + ref + '/qr.png?token=' + token).status_code, 200)


if __name__ == '__main__':
    unittest.main()
