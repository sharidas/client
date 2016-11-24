/*
 *    This software is in the public domain, furnished "as is", without technical
 *    support, and with no warranty, express or implied, as to its usefulness for
 *    any purpose.
 *
 */

#include <QtTest>
#include "syncenginetestutils.h"
#include <syncengine.h>

using namespace OCC;

bool itemDidComplete(const QSignalSpy &spy, const QString &path)
{
    for(const QList<QVariant> &args : spy) {
        SyncFileItem item = args[0].value<SyncFileItem>();
        if (item.destination() == path)
            return true;
    }
    return false;
}

bool itemDidCompleteSuccessfully(const QSignalSpy &spy, const QString &path)
{
    for(const QList<QVariant> &args : spy) {
        SyncFileItem item = args[0].value<SyncFileItem>();
        if (item.destination() == path)
            return item._status == SyncFileItem::Success;
    }
    return false;
}

SyncFileItem::Status itemDidCompleteWithStatus(const QSignalSpy &spy, const QString &path)
{
    for(const QList<QVariant> &args : spy) {
        SyncFileItem item = args[0].value<SyncFileItem>();
        if (item.destination() == path)
            return item._status;
    }
    return SyncFileItem::NoStatus;
}

class TestSyncEngine : public QObject
{
    Q_OBJECT

private slots:
    void testFileDownload() {
        FakeFolder fakeFolder{FileInfo::A12_B12_C12_S12()};
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.remoteModifier().insert("A/a0");
        fakeFolder.syncOnce();
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "A/a0"));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testFileUpload() {
        FakeFolder fakeFolder{FileInfo::A12_B12_C12_S12()};
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.localModifier().insert("A/a0");
        fakeFolder.syncOnce();
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "A/a0"));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testFileUploadBundled() {
        FakeFolder fakeFolder{FileInfo::A12_B12_C12_S12()};

        QVariantMap capBundle;
        capBundle["bundlerequest"] = "1.0";
        QVariantMap caps;
        caps["dav"] = capBundle;
        fakeFolder.getAccount()->setCapabilities(caps);

        //testFileUploadBundledAllFilesOK(fakeFolder);
        //testFileUploadBundledErrorForFile(fakeFolder);

        //TODO unfinished, cannot generate NetworkError
        //testFileUploadBundledNotHomeCollection(fakeFolder);
    }

    void testFileUploadBundledAllFilesOK(FakeFolder &fakeFolder) {
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.localModifier().insert("A/a3");
        fakeFolder.localModifier().insert("A/a4");
        fakeFolder.syncOnce();

        //check separate files
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "A/a3"));
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "A/a4"));

        //check whole bundle
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, ""));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testFileUploadBundledErrorForFile(FakeFolder &fakeFolder) {
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.localModifier().insert("A/a5");
        fakeFolder.localModifier().insert("A/normalerrorfile");
        fakeFolder.localModifier().insert("A/fatalerrorfile");
        fakeFolder.localModifier().insert("A/softerrorfile");
        fakeFolder.syncOnce();

        //check separate files
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "A/a5"));
        QVERIFY(SyncFileItem::NormalError == itemDidCompleteWithStatus(completeSpy, "A/normalerrorfile"));
        QVERIFY(SyncFileItem::FatalError == itemDidCompleteWithStatus(completeSpy, "A/fatalerrorfile"));
        QVERIFY(SyncFileItem::SoftError == itemDidCompleteWithStatus(completeSpy, "A/softerrorfile"));

        //check whole bundle
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, ""));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testFileUploadBundledNotHomeCollection(FakeFolder &fakeFolder) {
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.localModifier().insert("A/a7");
        fakeFolder.localModifier().insert("A/a8");
        fakeFolder.localModifier().insert("B/b4");

        //add the user "erroruser" which is not a FilesHomeCollection
        fakeFolder.getAccount()->setUrl(QUrl(QStringLiteral("http://erroruser:admin@localhost/owncloud")));
        fakeFolder.syncOnce();

        //check whole bundle
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, ""));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testDirDownload() {
        FakeFolder fakeFolder{FileInfo::A12_B12_C12_S12()};
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.remoteModifier().mkdir("Y");
        fakeFolder.remoteModifier().mkdir("Z");
        fakeFolder.remoteModifier().insert("Z/d0");
        fakeFolder.syncOnce();
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "Y"));
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "Z"));
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "Z/d0"));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testDirUpload() {
        FakeFolder fakeFolder{FileInfo::A12_B12_C12_S12()};
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.localModifier().mkdir("Y");
        fakeFolder.localModifier().mkdir("Z");
        fakeFolder.localModifier().insert("Z/d0");
        fakeFolder.syncOnce();
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "Y"));
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "Z"));
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "Z/d0"));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testLocalDelete() {
        FakeFolder fakeFolder{FileInfo::A12_B12_C12_S12()};
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.remoteModifier().remove("A/a1");
        fakeFolder.syncOnce();
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "A/a1"));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testRemoteDelete() {
        FakeFolder fakeFolder{FileInfo::A12_B12_C12_S12()};
        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        fakeFolder.localModifier().remove("A/a1");
        fakeFolder.syncOnce();
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "A/a1"));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testEmlLocalChecksum() {
        FakeFolder fakeFolder{FileInfo{}};
        fakeFolder.localModifier().insert("a1.eml", 64, 'A');
        fakeFolder.localModifier().insert("a2.eml", 64, 'A');
        fakeFolder.localModifier().insert("a3.eml", 64, 'A');
        // Upload and calculate the checksums
        // fakeFolder.syncOnce();
        fakeFolder.syncOnce();

        QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
        // Touch the file without changing the content, shouldn't upload
        fakeFolder.localModifier().setContents("a1.eml", 'A');
        // Change the content/size
        fakeFolder.localModifier().setContents("a2.eml", 'B');
        fakeFolder.localModifier().appendByte("a3.eml");
        fakeFolder.syncOnce();

        QVERIFY(!itemDidComplete(completeSpy, "a1.eml"));
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "a2.eml"));
        QVERIFY(itemDidCompleteSuccessfully(completeSpy, "a3.eml"));
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
    }

    void testRemoteChangeInMovedFolder() {
        // issue #5192
        FakeFolder fakeFolder{FileInfo{ QString(), {
            FileInfo { QStringLiteral("folder"), {
                FileInfo{ QStringLiteral("folderA"), { { QStringLiteral("file.txt"), 400 } } },
                QStringLiteral("folderB")
            }
        }}}};

        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());

        // Edit a file in a moved directory.
        fakeFolder.remoteModifier().setContents("folder/folderA/file.txt", 'a');
        fakeFolder.remoteModifier().rename("folder/folderA", "folder/folderB/folderA");
        fakeFolder.syncOnce();
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
        auto oldState = fakeFolder.currentLocalState();
        QVERIFY(oldState.find("folder/folderB/folderA/file.txt"));
        QVERIFY(!oldState.find("folder/folderA/file.txt"));

        // This sync should not remove the file
        fakeFolder.syncOnce();
        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
        QCOMPARE(fakeFolder.currentLocalState(), oldState);

    }

    void testSelectiveSyncModevFolder() {
        // issue #5224
        FakeFolder fakeFolder{FileInfo{ QString(), {
            FileInfo { QStringLiteral("parentFolder"), {
                FileInfo{ QStringLiteral("subFolderA"), { { QStringLiteral("fileA.txt"), 400 } } },
                FileInfo{ QStringLiteral("subFolderB"), { { QStringLiteral("fileB.txt"), 400 } } }
            }
        }}}};

        QCOMPARE(fakeFolder.currentLocalState(), fakeFolder.currentRemoteState());
        auto expectedServerState = fakeFolder.currentRemoteState();

        // Remove subFolderA with selectiveSync:
        fakeFolder.syncEngine().journal()->setSelectiveSyncList(SyncJournalDb::SelectiveSyncBlackList,
                                                                {"parentFolder/subFolderA/"});
        fakeFolder.syncEngine().journal()->avoidReadFromDbOnNextSync("parentFolder/subFolderA/");

        fakeFolder.syncOnce();

        {
            // Nothing changed on the server
            QCOMPARE(fakeFolder.currentRemoteState(), expectedServerState);
            // The local state should not have subFolderA
            auto remoteState = fakeFolder.currentRemoteState();
            remoteState.remove("parentFolder/subFolderA");
            QCOMPARE(fakeFolder.currentLocalState(), remoteState);
        }

        // Rename parentFolder on the server
        fakeFolder.remoteModifier().rename("parentFolder", "parentFolderRenamed");
        expectedServerState = fakeFolder.currentRemoteState();
        fakeFolder.syncOnce();

        {
            QCOMPARE(fakeFolder.currentRemoteState(), expectedServerState);
            auto remoteState = fakeFolder.currentRemoteState();
            // The subFolderA should still be there on the server.
            QVERIFY(remoteState.find("parentFolderRenamed/subFolderA/fileA.txt"));
            // But not on the client because of the selective sync
            remoteState.remove("parentFolderRenamed/subFolderA");
            QCOMPARE(fakeFolder.currentLocalState(), remoteState);
        }

        // Rename it again, locally this time.
        fakeFolder.localModifier().rename("parentFolderRenamed", "parentThirdName");
        fakeFolder.syncOnce();

        {
            auto remoteState = fakeFolder.currentRemoteState();
            // The subFolderA should still be there on the server.
            QVERIFY(remoteState.find("parentThirdName/subFolderA/fileA.txt"));
            // But not on the client because of the selective sync
            remoteState.remove("parentThirdName/subFolderA");
            QCOMPARE(fakeFolder.currentLocalState(), remoteState);

            expectedServerState = fakeFolder.currentRemoteState();
            QSignalSpy completeSpy(&fakeFolder.syncEngine(), SIGNAL(itemCompleted(const SyncFileItem &, const PropagatorJob &)));
            fakeFolder.syncOnce(); // This sync should do nothing
            QCOMPARE(completeSpy.count(), 0);

            QCOMPARE(fakeFolder.currentRemoteState(), expectedServerState);
            QCOMPARE(fakeFolder.currentLocalState(), remoteState);
        }
    }

};

QTEST_GUILESS_MAIN(TestSyncEngine)
#include "testsyncengine.moc"
